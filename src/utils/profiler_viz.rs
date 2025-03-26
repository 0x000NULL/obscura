//! Profiler visualization tools
//!
//! This module provides visualization tools for profiler data to help
//! identify and analyze critical paths in the system.

use std::collections::HashMap;
use std::time::Duration;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use super::profiler::{GLOBAL_PROFILER, ProfileStats};
use colored::*;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;

/// Format for visualization output
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Text-based visualization
    Text,
    /// HTML format for browser viewing
    Html,
    /// JSON format for external tools
    Json,
    /// CSV format for spreadsheet software
    Csv,
    /// Flame graph input format
    FlameGraph,
}

/// Generate a visualization of profiling data
pub fn generate_visualization(
    format: OutputFormat,
    categories: Option<Vec<String>>,
    output_path: Option<&str>,
) -> io::Result<String> {
    // Get all stats from the global profiler
    let stats = GLOBAL_PROFILER.get_all_stats();
    
    // Filter by categories if specified
    let filtered_stats = if let Some(ref cats) = categories {
        stats.into_iter()
            .filter(|s| cats.contains(&s.category))
            .collect::<Vec<_>>()
    } else {
        stats
    };
    
    // Generate the appropriate format
    let output = match format {
        OutputFormat::Text => generate_text_visualization(&filtered_stats),
        OutputFormat::Html => generate_html_visualization(&filtered_stats),
        OutputFormat::Json => generate_json_visualization(&filtered_stats)?,
        OutputFormat::Csv => generate_csv_visualization(&filtered_stats),
        OutputFormat::FlameGraph => generate_flamegraph_visualization(&filtered_stats),
    };
    
    // Write to file if specified
    if let Some(path) = output_path {
        let mut file = File::create(path)?;
        file.write_all(output.as_bytes())?;
    }
    
    Ok(output)
}

/// Generate a simple text-based visualization
fn generate_text_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // Group stats by category
    let mut by_category: HashMap<String, Vec<ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category
            .entry(stat.category.clone())
            .or_insert_with(Vec::new)
            .push(stat.clone());
    }
    
    // Calculate total time
    let total_time: Duration = stats.iter()
        .map(|s| *s.total_time.lock().unwrap())
        .sum();
    
    // Add header
    output.push_str(&format!("Profiling Report (Total Time: {:?})\n\n", total_time));
    
    // Add stats by category
    for (category, mut cat_stats) in by_category {
        output.push_str(&format!("=== {} ===\n", category));
        
        // Sort by total time
        cat_stats.sort_by(|a, b| {
            b.total_time.lock().unwrap().cmp(&a.total_time.lock().unwrap())
        });
        
        for stat in cat_stats {
            let total = *stat.total_time.lock().unwrap();
            let min = *stat.min_time.lock().unwrap();
            let max = *stat.max_time.lock().unwrap();
            let avg = stat.average_time();
            let std_dev = stat.std_deviation();
            let calls = stat.call_count.load(Ordering::SeqCst);
            let calls_per_sec = stat.calls_per_second();
            
            output.push_str(&format!(
                "  {}:\n    Calls: {}\n    Total Time: {:?}\n    Avg Time: {:?}\n    Min Time: {:?}\n    Max Time: {:?}\n    Std Dev: {:?}\n    Calls/sec: {:.2}\n\n",
                stat.name, calls, total, avg, min, max, std_dev, calls_per_sec
            ));
        }
    }
    
    output
}

/// Generate an HTML visualization
fn generate_html_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // Group stats by category
    let mut by_category: HashMap<String, Vec<ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category
            .entry(stat.category.clone())
            .or_insert_with(Vec::new)
            .push(stat.clone());
    }
    
    // Calculate total time
    let total_time: Duration = stats.iter()
        .map(|s| *s.total_time.lock().unwrap())
        .sum();
    
    // Generate HTML
    output.push_str(r#"<!DOCTYPE html>
<html>
<head>
    <title>Profiling Report</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .category { margin-bottom: 20px; }
        .operation { margin-left: 20px; }
        .bar { background-color: #4CAF50; height: 20px; }
    </style>
</head>
<body>
    <h1>Profiling Report</h1>
    <p>Total Time: "#);
    output.push_str(&format!("{:?}", total_time));
    output.push_str(r#"</p>
"#);
    
    // Add stats by category
    for (category, mut cat_stats) in by_category {
        output.push_str(&format!("<div class='category'>\n<h2>{}</h2>\n", category));
        
        // Sort by total time
        cat_stats.sort_by(|a, b| {
            b.total_time.lock().unwrap().cmp(&a.total_time.lock().unwrap())
        });
        
        for stat in cat_stats {
            let total = *stat.total_time.lock().unwrap();
            let min = *stat.min_time.lock().unwrap();
            let max = *stat.max_time.lock().unwrap();
            let avg = stat.average_time();
            let std_dev = stat.std_deviation();
            let calls = stat.call_count.load(Ordering::SeqCst);
            let calls_per_sec = stat.calls_per_second();
            
            let percentage = if total_time.as_nanos() > 0 {
                (total.as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            output.push_str(&format!(
                r#"<div class='operation'>
    <h3>{}</h3>
    <p>Calls: {}</p>
    <p>Total Time: {:?}</p>
    <p>Avg Time: {:?}</p>
    <p>Min Time: {:?}</p>
    <p>Max Time: {:?}</p>
    <p>Std Dev: {:?}</p>
    <p>Calls/sec: {:.2}</p>
    <div class='bar' style='width: {}%'></div>
</div>
"#,
                stat.name, calls, total, avg, min, max, std_dev, calls_per_sec, percentage
            ));
        }
        output.push_str("</div>\n");
    }
    
    output.push_str(r#"</body>
</html>"#);
    
    output
}

/// Generate JSON visualization
fn generate_json_visualization(stats: &[ProfileStats]) -> io::Result<String> {
    let mut output = String::new();
    
    // Group stats by category
    let mut by_category: HashMap<String, Vec<ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category
            .entry(stat.category.clone())
            .or_insert_with(Vec::new)
            .push(stat.clone());
    }
    
    // Calculate total time
    let total_time: Duration = stats.iter()
        .map(|s| *s.total_time.lock().unwrap())
        .sum();
    
    // Start JSON object
    output.push_str(&format!(
        r#"{{"total_time": {:?}, "categories": {{"#,
        total_time
    ));
    
    // Add stats by category
    let mut first_category = true;
    for (category, mut cat_stats) in by_category {
        if !first_category {
            output.push_str(",");
        }
        first_category = false;
        
        output.push_str(&format!("\n  \"{}\": [", category));
        
        // Sort by total time
        cat_stats.sort_by(|a, b| {
            b.total_time.lock().unwrap().cmp(&a.total_time.lock().unwrap())
        });
        
        let mut first_stat = true;
        for stat in cat_stats {
            if !first_stat {
                output.push_str(",");
            }
            first_stat = false;
            
            let total = *stat.total_time.lock().unwrap();
            let min = *stat.min_time.lock().unwrap();
            let max = *stat.max_time.lock().unwrap();
            let avg = stat.average_time();
            let std_dev = stat.std_deviation();
            let calls = stat.call_count.load(Ordering::SeqCst);
            let calls_per_sec = stat.calls_per_second();
            
            output.push_str(&format!(
                r#"
    {{
      "name": "{}",
      "calls": {},
      "total_time": {:?},
      "avg_time": {:?},
      "min_time": {:?},
      "max_time": {:?},
      "std_dev": {:?},
      "calls_per_second": {:.2}
    }}"#,
                stat.name, calls, total, avg, min, max, std_dev, calls_per_sec
            ));
        }
        
        output.push_str("\n  ]");
    }
    
    output.push_str("\n}}");
    
    Ok(output)
}

/// Generate CSV visualization
fn generate_csv_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // Add CSV header
    output.push_str("Category,Name,Calls,Total Time,Avg Time,Min Time,Max Time,Std Dev,Calls/sec\n");
    
    // Sort stats by total time
    let mut sorted_stats = stats.to_vec();
    sorted_stats.sort_by(|a, b| {
        b.total_time.lock().unwrap().cmp(&a.total_time.lock().unwrap())
    });
    
    // Add data rows
    for stat in sorted_stats {
        let total = *stat.total_time.lock().unwrap();
        let min = *stat.min_time.lock().unwrap();
        let max = *stat.max_time.lock().unwrap();
        let avg = stat.average_time();
        let std_dev = stat.std_deviation();
        let calls = stat.call_count.load(Ordering::SeqCst);
        let calls_per_sec = stat.calls_per_second();
        
        output.push_str(&format!(
            "{},{},{},{:?},{:?},{:?},{:?},{:?},{:.2}\n",
            stat.category,
            stat.name,
            calls,
            total,
            avg,
            min,
            max,
            std_dev,
            calls_per_sec
        ));
    }
    
    output
}

/// Generate flame graph visualization
fn generate_flamegraph_visualization(stats: &[ProfileStats]) -> String {
    let mut output = String::new();
    
    // Sort stats by total time
    let mut sorted_stats = stats.to_vec();
    sorted_stats.sort_by(|a, b| {
        b.total_time.lock().unwrap().cmp(&a.total_time.lock().unwrap())
    });
    
    // Generate flame graph input format
    for stat in sorted_stats {
        let total = *stat.total_time.lock().unwrap();
        let calls = stat.call_count.load(Ordering::SeqCst);
        
        // Format: name;category;calls;total_time
        output.push_str(&format!(
            "{};{};{};{}\n",
            stat.name,
            stat.category,
            calls,
            total.as_nanos()
        ));
    }
    
    output
}

/// Print a colored report to the console
pub fn print_colored_report(stats: &[ProfileStats]) {
    println!("{}", "Critical Path Report".bright_white().bold());
    println!("{}", "===================".bright_white());
    println!();
    
    // Calculate total values
    let total_time: Duration = stats.iter().map(|s| s.get_total_time()).sum();
    let total_calls: usize = stats.iter().map(|s| s.get_call_count()).sum();
    
    println!("Total Time: {}", format!("{:?}", total_time).cyan());
    println!("Total Calls: {}", total_calls.to_string().cyan());
    println!();
    
    // Group by category
    let mut by_category: HashMap<String, Vec<ProfileStats>> = HashMap::new();
    for stat in stats {
        by_category.entry(stat.category.clone())
            .or_default()
            .push(stat.clone());
    }
    
    // Print each category
    for (category, cat_stats) in by_category.iter_mut() {
        println!("Category: {}", category.yellow());
        println!("{}", "----------".yellow());
        
        // Sort by total time
        cat_stats.sort_by(|a, b| b.get_total_time().cmp(&a.get_total_time()));
        
        for stat in cat_stats.iter() {
            let percentage = if total_time.as_nanos() > 0 {
                (stat.get_total_time().as_nanos() as f64 / total_time.as_nanos() as f64) * 100.0
            } else {
                0.0
            };
            
            println!("  {} - {}",
                stat.name.bright_white(),
                format!("{:.2}%", percentage).cyan()
            );
            println!("    Calls: {}", stat.get_call_count().to_string().green());
            println!("    Total Time: {:?}", stat.get_total_time());
            println!("    Avg Time: {:?}", stat.average_time());
            println!();
        }
    }
}

/// Generate a full visualization suite
pub fn generate_full_visualization(
    output_dir: &str,
    categories: Option<Vec<String>>,
) -> io::Result<()> {
    // Create output directory if it doesn't exist
    std::fs::create_dir_all(output_dir)?;
    
    // Generate all formats
    let formats = [
        (OutputFormat::Text, "profile.txt"),
        (OutputFormat::Html, "profile.html"),
        (OutputFormat::Json, "profile.json"),
        (OutputFormat::Csv, "profile.csv"),
        (OutputFormat::FlameGraph, "profile.folded"),
    ];
    
    for (format, filename) in formats.iter() {
        let path = Path::new(output_dir).join(filename);
        generate_visualization(*format, categories.clone(), Some(path.to_str().unwrap()))?;
    }
    
    Ok(())
}

fn format_name(format: OutputFormat) -> &'static str {
    match format {
        OutputFormat::Text => "text",
        OutputFormat::Html => "html",
        OutputFormat::Json => "json",
        OutputFormat::Csv => "csv",
        OutputFormat::FlameGraph => "flamegraph",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    
    #[test]
    fn test_text_visualization() {
        let stats = vec![
            ProfileStats::new("op1", "cat1"),
            ProfileStats::new("op2", "cat1"),
            ProfileStats::new("op3", "cat2"),
        ];
        
        // Add some measurements
        stats[0].record(Duration::from_micros(100));
        stats[1].record(Duration::from_micros(200));
        stats[2].record(Duration::from_micros(300));
        
        let viz = generate_text_visualization(&stats);
        assert!(viz.contains("Critical Path Visualization"));
        assert!(viz.contains("cat1"));
        assert!(viz.contains("cat2"));
        assert!(viz.contains("op1"));
        assert!(viz.contains("op2"));
        assert!(viz.contains("op3"));
    }
    
    #[test]
    fn test_html_visualization() {
        let stats = vec![
            ProfileStats::new("op1", "cat1"),
            ProfileStats::new("op2", "cat2"),
        ];
        
        stats[0].record(Duration::from_micros(100));
        stats[1].record(Duration::from_micros(200));
        
        let viz = generate_html_visualization(&stats);
        assert!(viz.contains("<!DOCTYPE html>"));
        assert!(viz.contains("op1"));
        assert!(viz.contains("op2"));
        assert!(viz.contains("cat1"));
        assert!(viz.contains("cat2"));
    }
    
    #[test]
    fn test_csv_visualization() {
        let stats = vec![
            ProfileStats::new("op1", "cat1"),
            ProfileStats::new("op2", "cat1"),
        ];
        
        stats[0].record(Duration::from_micros(100));
        stats[1].record(Duration::from_micros(200));
        
        let viz = generate_csv_visualization(&stats);
        assert!(viz.contains("Name,Category,Calls"));
        assert!(viz.contains("op1,cat1"));
        assert!(viz.contains("op2,cat1"));
    }
} 