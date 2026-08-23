use qanvuli_core::database::CapecEntry;
use std::collections::{HashMap, HashSet};

pub(super) struct CapecTree {
    pub(super) entries: Vec<CapecEntry>,
    pub(super) paths: Vec<Vec<i32>>,
    pub(super) prefixes: Vec<String>,
}

pub(super) fn project_capec_tree(entries: Vec<CapecEntry>) -> CapecTree {
    let by_id = entries
        .iter()
        .cloned()
        .map(|entry| (entry.id, entry))
        .collect::<HashMap<_, _>>();
    let mut children = HashMap::<i32, Vec<i32>>::new();
    let mut roots = Vec::new();
    for entry in &entries {
        if entry.parent_ids.is_empty() {
            roots.push(entry.id);
        }
        for parent_id in &entry.parent_ids {
            children.entry(*parent_id).or_default().push(entry.id);
        }
    }
    roots.sort_unstable();
    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }
    let mut tree = CapecTree {
        entries: Vec::new(),
        paths: Vec::new(),
        prefixes: Vec::new(),
    };
    for root in roots {
        append_capec_branch(
            root,
            &by_id,
            &children,
            &mut HashSet::new(),
            &mut Vec::new(),
            &mut tree,
        );
    }
    let visible = tree
        .entries
        .iter()
        .map(|entry| entry.id)
        .collect::<HashSet<_>>();
    for entry in entries {
        if !visible.contains(&entry.id) {
            append_capec_branch(
                entry.id,
                &by_id,
                &children,
                &mut HashSet::new(),
                &mut Vec::new(),
                &mut tree,
            );
        }
    }
    tree.prefixes = capec_tree_prefixes(&tree.paths);
    tree
}

pub(super) fn filter_capec_tree(tree: CapecTree, matched: &HashSet<i32>) -> CapecTree {
    let mut visible_paths = HashSet::<Vec<i32>>::new();
    for path in &tree.paths {
        if path.last().is_some_and(|id| matched.contains(id)) {
            for length in 1..=path.len() {
                visible_paths.insert(path[..length].to_vec());
            }
        }
    }
    let mut filtered = CapecTree {
        entries: Vec::new(),
        paths: Vec::new(),
        prefixes: Vec::new(),
    };
    for (entry, path) in tree.entries.into_iter().zip(tree.paths) {
        if visible_paths.contains(&path) {
            filtered.entries.push(entry);
            filtered.paths.push(path);
        }
    }
    filtered.prefixes = capec_tree_prefixes(&filtered.paths);
    filtered
}

fn capec_tree_prefixes(paths: &[Vec<i32>]) -> Vec<String> {
    let mut children = HashMap::<Vec<i32>, Vec<i32>>::new();
    for path in paths {
        if path.len() > 1 {
            let parent = path[..path.len() - 1].to_vec();
            let child = *path.last().expect("non-empty CAPEC path");
            let siblings = children.entry(parent).or_default();
            if !siblings.contains(&child) {
                siblings.push(child);
            }
        }
    }
    paths
        .iter()
        .map(|path| {
            if path.len() == 1 {
                return String::new();
            }
            let mut prefix = String::new();
            for depth in 1..path.len() - 1 {
                let parent = path[..depth].to_vec();
                let continues = children
                    .get(&parent)
                    .and_then(|siblings| siblings.last())
                    .is_some_and(|last| *last != path[depth]);
                prefix.push_str(if continues { "│  " } else { "   " });
            }
            let parent = path[..path.len() - 1].to_vec();
            let is_last = children
                .get(&parent)
                .and_then(|siblings| siblings.last())
                .is_some_and(|last| Some(last) == path.last());
            prefix.push_str(if is_last { "└─ " } else { "├─ " });
            prefix
        })
        .collect()
}

fn append_capec_branch(
    id: i32,
    entries: &HashMap<i32, CapecEntry>,
    children: &HashMap<i32, Vec<i32>>,
    seen: &mut HashSet<i32>,
    path: &mut Vec<i32>,
    tree: &mut CapecTree,
) {
    if !seen.insert(id) {
        return;
    }
    if let Some(entry) = entries.get(&id) {
        path.push(id);
        tree.entries.push(entry.clone());
        tree.paths.push(path.clone());
        tree.prefixes.push(String::new());
        if let Some(child_ids) = children.get(&id) {
            for child_id in child_ids {
                append_capec_branch(*child_id, entries, children, seen, path, tree);
            }
        }
        path.pop();
    }
    seen.remove(&id);
}
