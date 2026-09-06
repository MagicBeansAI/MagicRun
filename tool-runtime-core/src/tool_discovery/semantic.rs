use std::cmp::Ordering;

use anyhow::Result;
use tokio::sync::RwLock;

use crate::{config::SemanticSearchConfig, registry::types::ToolDefinition};

#[derive(Debug, Clone)]
pub struct SemanticMatch {
    pub tool_name: String,
    pub similarity_score: f64,
    pub enabled: bool,
    pub hidden: bool,
}

#[derive(Debug, Clone)]
struct IndexedTool {
    name: String,
    description: String,
    categories: Vec<String>,
    enabled: bool,
    hidden: bool,
}

pub struct SemanticSearchService {
    config: SemanticSearchConfig,
    // In this branch, ranking is lexical and category-overlap based.
    // We keep the SemanticSearch interface stable for callers.
    index: RwLock<Vec<IndexedTool>>,
}

impl SemanticSearchService {
    pub fn new(config: SemanticSearchConfig) -> Self {
        Self {
            config,
            index: RwLock::new(vec![]),
        }
    }

    pub async fn initialize(&self) -> Result<()> {
        Ok(())
    }

    pub async fn replace_index(&self, tools: Vec<ToolDefinition>) {
        let new_index: Vec<IndexedTool> = tools
            .into_iter()
            .map(|tool| IndexedTool {
                name: tool.name,
                description: tool.description,
                categories: tool.categories,
                enabled: tool.enabled,
                hidden: tool.hidden,
            })
            .collect();

        let mut guard = self.index.write().await;
        *guard = new_index;
    }

    pub async fn search_all_tools_with_scores(&self, query: &str) -> Result<Vec<SemanticMatch>> {
        let query = query.trim();
        if query.is_empty() {
            return Ok(vec![]);
        }

        let index = self.index.read().await;
        let mut scored: Vec<SemanticMatch> = index
            .iter()
            .map(|tool| {
                let score = lexical_similarity(query, tool);
                SemanticMatch {
                    tool_name: tool.name.clone(),
                    similarity_score: score,
                    enabled: tool.enabled,
                    hidden: tool.hidden,
                }
            })
            .filter(|match_result| {
                match_result.similarity_score >= self.config.similarity_threshold
            })
            .collect();

        scored.sort_by(|a, b| {
            b.similarity_score
                .partial_cmp(&a.similarity_score)
                .unwrap_or(Ordering::Equal)
        });
        // Keep only top-N results as configured by semantic_search.max_results.
        scored.truncate(self.config.max_results.max(1));

        Ok(scored)
    }

    pub async fn search_categories(
        &self,
        category: &str,
        top_k: usize,
    ) -> Result<Vec<(String, f32)>> {
        let category = category.trim().to_lowercase();
        if category.is_empty() {
            return Ok(vec![]);
        }

        let index = self.index.read().await;
        let mut matches: Vec<(String, f32)> = vec![];

        for tool in index.iter() {
            for tool_category in &tool.categories {
                let score = category_similarity(&category, tool_category);
                if score > 0.0 {
                    matches.push((tool_category.clone(), score));
                }
            }
        }

        matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        matches.dedup_by(|a, b| a.0 == b.0);
        matches.truncate(top_k);

        Ok(matches)
    }
}

fn lexical_similarity(query: &str, tool: &IndexedTool) -> f64 {
    let query = query.to_lowercase();
    let name = tool.name.to_lowercase();
    let description = tool.description.to_lowercase();

    if query == name {
        return 1.0;
    }

    let mut score = 0.0_f64;

    if name.contains(&query) {
        score += 0.8;
    }
    if description.contains(&query) {
        score += 0.6;
    }

    for token in query.split_whitespace().filter(|token| token.len() > 2) {
        if name.contains(token) {
            score += 0.2;
        }
        if description.contains(token) {
            score += 0.1;
        }
        if tool
            .categories
            .iter()
            .any(|category| category.to_lowercase().contains(token))
        {
            score += 0.1;
        }
    }

    score.min(1.0)
}

fn category_similarity(query_category: &str, candidate: &str) -> f32 {
    let candidate_lower = candidate.to_lowercase();

    if query_category == candidate_lower {
        return 1.0;
    }

    if candidate_lower.contains(query_category) || query_category.contains(&candidate_lower) {
        return 0.7;
    }

    0.0
}
