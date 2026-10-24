//! Golden test: the verdict cells of the README's "Firewall tiers" table equal
//! `policy::tier::GATE_TABLE`, row for row. Only the four verdict cells are compared; the row
//! labels are prose and may differ.

use safe_ai_skill::policy::tier::GATE_TABLE;

/// The data rows of the first Markdown table under `## Firewall tiers`, as cell lists.
fn readme_rows() -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split("\n## Firewall tiers\n")
        .nth(1)
        .expect("README has a `## Firewall tiers` section");
    let section = section.split("\n## ").next().unwrap_or(section);
    let mut rows = Vec::new();
    let mut in_table = false;
    for line in section.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            if in_table {
                break;
            }
            continue;
        }
        in_table = true;
        // `\|` inside a cell is a literal pipe.
        let cells: Vec<String> = line
            .trim_matches('|')
            .replace("\\|", "\u{0}")
            .split('|')
            .map(|c| c.trim().replace('\u{0}', "|"))
            .collect();
        rows.push(cells);
    }
    assert!(rows.len() > 2, "no table under `## Firewall tiers`");
    assert_eq!(rows[0][1..], ["Off", "Relaxed", "Medium", "High"], "header");
    assert!(rows[1]
        .iter()
        .all(|c| c.chars().all(|ch| ch == '-' || ch == ':')));
    rows.split_off(2)
}

#[test]
fn readme_tier_table_verdicts_match_the_engine_table() {
    let rows = readme_rows();
    assert_eq!(
        rows.len(),
        GATE_TABLE.len(),
        "README rows vs GATE_TABLE rows"
    );
    for (i, (row, (label, cells))) in rows.iter().zip(GATE_TABLE).enumerate() {
        assert_eq!(
            row.len(),
            5,
            "README row {i} ({}) has {} cells",
            row[0],
            row.len()
        );
        assert_eq!(
            row[1..],
            cells[..],
            "README row {i} `{}` vs GATE_TABLE `{label}`",
            row[0]
        );
    }
}
