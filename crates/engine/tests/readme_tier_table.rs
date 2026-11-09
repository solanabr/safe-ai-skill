//! Golden test: the verdict cells of the per-gate table under `## Behaviour per gate` in
//! `docs/tiers.md` equal `policy::tier::GATE_TABLE`, row for row. Only the four verdict cells
//! are compared; the row labels are prose and may differ. The README carries only a short
//! summary of the tiers, not this table. Keep the `## Behaviour per gate` heading stable:
//! this test anchors on it.

use safe_ai_skill::policy::tier::GATE_TABLE;

/// The data rows of the first Markdown table under `## Behaviour per gate`, as cell lists.
fn readme_rows() -> Vec<Vec<String>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/tiers.md");
    let text = std::fs::read_to_string(path).unwrap();
    let section = text
        .split("\n## Behaviour per gate\n")
        .nth(1)
        .expect("docs/tiers.md has a `## Behaviour per gate` section");
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
    assert!(rows.len() > 2, "no table under `## Behaviour per gate`");
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
        "docs/tiers.md rows vs GATE_TABLE rows"
    );
    for (i, (row, (label, cells))) in rows.iter().zip(GATE_TABLE).enumerate() {
        assert_eq!(
            row.len(),
            5,
            "tiers.md row {i} ({}) has {} cells",
            row[0],
            row.len()
        );
        assert_eq!(
            row[1..],
            cells[..],
            "tiers.md row {i} `{}` vs GATE_TABLE `{label}`",
            row[0]
        );
    }
}
