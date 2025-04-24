//! Pattern matching utilities

/// Find a pattern in binary data
pub fn find_pattern(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|window| window == pattern)
}

/// Find a pattern and extract the following text until a delimiter
pub fn extract_after_pattern(data: &[u8], pattern: &[u8], delimiters: &[u8]) -> Option<String> {
    for (i, window) in data.windows(pattern.len()).enumerate() {
        if window == pattern {
            let start = i + pattern.len();
            let mut end = start;
            
            while end < data.len() && !delimiters.contains(&data[end]) {
                end += 1;
            }
            
            if end > start {
                return std::str::from_utf8(&data[start..end]).ok().map(|s| s.to_string());
            }
        }
    }
    
    None
} 