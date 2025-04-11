import re
import sys
from collections import defaultdict

def parse_lex_file(file_path):
    """Extract sections from a Lex file."""
    with open(file_path, 'r') as file:
        lines = file.readlines()

    definitions, rules, user_code = [], [], []
    section = 1

    for line in lines:
        if '%%' in line:
            section += 1
            continue
        if section == 1:
            definitions.append(line.rstrip())
        elif section == 2:
            rules.append(line.rstrip())
        else:
            user_code.append(line.rstrip())

    return definitions, rules, user_code

def remove_unused_macros(definitions, rules):
    """Remove macros never used in rules."""
    used_macros = set()
    for rule in rules:
        used_macros.update(re.findall(r'{([^}]+)}', rule))

    optimized_defs = []
    unused = []

    for definition in definitions:
        match = re.match(r'^(\w+)\s+(.*)', definition)
        if match:
            name = match.group(1)
            if name in used_macros:
                optimized_defs.append(definition)
            else:
                unused.append(name)

    if unused:
        print("⚠️ Unused Macros:")
        for macro in unused:
            print(f"  - {macro}")
    return optimized_defs

def remove_unused_rules(rules, user_code):
    """Remove token rules never referenced in user code."""
    used_tokens = set(re.findall(r'\b[A-Z_][A-Z_0-9]*\b', ' '.join(user_code)))
    optimized_rules = []

    for rule in rules:
        match = re.match(r'(\S+)\s+(.*)', rule)
        if match:
            pattern, action = match.groups()
            if '{' in action or any(token in action for token in used_tokens):
                optimized_rules.append(rule)
    return optimized_rules

def inline_macros(rules, definitions):
    """Inline macros used only once directly into rules."""
    macro_map = {}
    usage_count = defaultdict(int)

    for definition in definitions:
        parts = re.match(r'^(\w+)\s+(.*)', definition)
        if parts:
            macro, pattern = parts.groups()
            macro_map[macro] = pattern

    for rule in rules:
        for macro in macro_map:
            if f'{{{macro}}}' in rule:
                usage_count[macro] += 1

    for i, rule in enumerate(rules):
        for macro, count in usage_count.items():
            if count == 1:
                rules[i] = rules[i].replace(f'{{{macro}}}', macro_map[macro])
    return rules

def merge_similar_rules(rules):
    """Group rules with identical actions."""
    action_to_patterns = defaultdict(list)

    for rule in rules:
        match = re.match(r'(.+?)\s+({.+})', rule)
        if match:
            pattern, action = match.groups()
            action_to_patterns[action.strip()].append(pattern.strip())
        else:
            action_to_patterns[""].append(rule)

    merged_rules = []
    for action, patterns in action_to_patterns.items():
        if not action:
            merged_rules.extend(patterns)
            continue
        if len(patterns) > 1:
            merged_pattern = ' | '.join(patterns)
        else:
            merged_pattern = patterns[0]
        merged_rules.append(f"{merged_pattern} {action}")
    return merged_rules

def simplify_regex(rules):
    """Simplify common regex patterns."""
    simplified = []
    for rule in rules:
        pattern_action = re.match(r'(.+?)\s+({.+})', rule)
        if pattern_action:
            pattern, action = pattern_action.groups()

            # Simplify common character classes
            pattern = pattern.replace('[0-9]', r'\d')
            pattern = pattern.replace('[ \t]', r'\s')
            pattern = pattern.replace('[a-zA-Z]', r'[A-Za-z]')
            pattern = re.sub(r'\[A-Za-z0-9\]', r'\\w', pattern)  # Fixed escaping issue

            simplified.append(f"{pattern} {action}")
        else:
            simplified.append(rule)
    return simplified

def group_and_comment_rules(rules):
    """Insert comments to group similar rules."""
    categorized = {'identifiers': [], 'literals': [], 'operators': [], 'ignored': [], 'others': []}

    for rule in rules:
        if re.search(r'identifier|IDENT', rule, re.IGNORECASE):
            categorized['identifiers'].append(rule)
        elif re.search(r'number|digit|[0-9]', rule, re.IGNORECASE):
            categorized['literals'].append(rule)
        elif re.search(r'[+\-*/=]|OPERATOR|EQ|ASSIGN', rule):
            categorized['operators'].append(rule)
        elif re.search(r'whitespace|comment|skip', rule, re.IGNORECASE):
            categorized['ignored'].append(rule)
        else:
            categorized['others'].append(rule)

    grouped = []
    for label, group in categorized.items():
        if group:
            grouped.append(f"// {label.capitalize()}")
            grouped.extend(group)
    return grouped

def optimize_lex_file(input_file, output_file):
    """Main optimization pipeline."""
    definitions, rules, user_code = parse_lex_file(input_file)

    definitions = remove_unused_macros(definitions, rules)
    rules = remove_unused_rules(rules, user_code)
    rules = inline_macros(rules, definitions)
    rules = merge_similar_rules(rules)
    rules = simplify_regex(rules)
    rules = group_and_comment_rules(rules)

    with open(output_file, 'w') as file:
        if definitions:
            file.write('\n'.join(definitions) + '\n')
        file.write('%%\n')
        file.write('\n'.join(rules) + '\n')
        file.write('%%\n')
        file.write('\n'.join(user_code) + '\n')

    print(f"\n✅ Optimization complete! Output saved to: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python lex_optimizer.py <input.l> <output.l>")
    else:
        optimize_lex_file(sys.argv[1], sys.argv[2])
