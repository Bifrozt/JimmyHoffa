"""
hoffa.kb — knowledge base subsystem.

Topic-organized flat files (kb/[topic].kb). Block format:
    ## blockname
    # tags: tag1, tag2
    # desc: one-line description
    body (raw, pasteable)

Retrieval: list_blocks / show_block / grep_blocks. Index built in-memory.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class KBBlock:
    """Represents a single KB block."""
    name: str
    topic: str
    tags: Set[str] = field(default_factory=set)
    description: str = ""
    body: str = ""

    def __str__(self) -> str:
        """Return formatted block for display."""
        lines = [
            f"## {self.name}",
            f"# topic: {self.topic}",
            f"# tags: {', '.join(sorted(self.tags)) if self.tags else '(none)'}",
            f"# desc: {self.description}",
            "",
            self.body,
        ]
        return "\n".join(lines)

    @property
    def searchable_text(self) -> str:
        """Combine all searchable fields for grep."""
        return f"{self.name} {self.description} {' '.join(self.tags)} {self.body}".lower()


class KnowledgeBase:
    """KB subsystem: parse, index, and retrieve blocks."""

    def __init__(self, kb_dir: Optional[Path] = None):
        """
        Initialize KB subsystem.

        Args:
            kb_dir: Path to kb/ directory. If None, defaults to a kb/ directory
                    that is a SIBLING of the package (i.e. <install_root>/kb),
                    matching the ~/bin deploy layout where hoffa/ and kb/ sit
                    side by side alongside the wrapper.
        """
        if kb_dir is None:
            kb_dir = Path(__file__).parent.parent / "kb"

        self.kb_dir = Path(kb_dir)
        self.blocks: List[KBBlock] = []
        self.index_by_name: Dict[str, KBBlock] = {}  # name -> KBBlock
        self.index_by_tag: Dict[str, List[KBBlock]] = {}  # tag -> [KBBlock, ...]
        self.index_by_topic: Dict[str, List[KBBlock]] = {}  # topic -> [KBBlock, ...]

    def ensure_kb_dir(self) -> None:
        """Create kb/ directory if it doesn't exist."""
        try:
            self.kb_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f"[!] Failed to create kb directory: {e}", file=sys.stderr)
            sys.exit(1)

    def load(self) -> None:
        """
        Parse all .kb files in kb_dir and build indices.
        Creates kb_dir if it doesn't exist.
        """
        self.ensure_kb_dir()

        # Find all .kb files
        kb_files = sorted(self.kb_dir.glob("*.kb"))

        if not kb_files:
            # Empty knowledge base is acceptable; user can populate later
            return

        for kb_file in kb_files:
            topic = kb_file.stem  # filename without .kb extension
            self._parse_kb_file(kb_file, topic)

        # Build indices
        for block in self.blocks:
            self.index_by_name[block.name] = block

            for tag in block.tags:
                if tag not in self.index_by_tag:
                    self.index_by_tag[tag] = []
                self.index_by_tag[tag].append(block)

            if block.topic not in self.index_by_topic:
                self.index_by_topic[block.topic] = []
            self.index_by_topic[block.topic].append(block)

    def _parse_kb_file(self, kb_file: Path, topic: str) -> None:
        """
        Parse a single .kb file and extract blocks.

        Format:
            # topic: <topic>
            # desc: <file description>

            ## blockname
            # tags: tag1, tag2, tag3
            # desc: one-line description

            Block body (commands, payloads, code, etc.)
            Can span multiple lines.
            Raw content, pasteable as-is.

        Args:
            kb_file: Path to .kb file
            topic: Topic name (derived from filename)
        """
        try:
            content = kb_file.read_text(encoding='utf-8')
        except Exception as e:
            print(f"[!] Failed to read {kb_file}: {e}", file=sys.stderr)
            return

        # Split into blocks by ## delimiter
        block_pattern = r"^##\s+(.+)$"
        lines = content.split('\n')

        current_block_name = None
        current_tags: Set[str] = set()
        current_desc = ""
        current_body_lines: List[str] = []

        for i, line in enumerate(lines):
            block_match = re.match(block_pattern, line)

            if block_match:
                # Save previous block if exists
                if current_block_name is not None:
                    self._save_block(
                        current_block_name, topic, current_tags,
                        current_desc, '\n'.join(current_body_lines).strip()
                    )

                # Start new block
                current_block_name = block_match.group(1).strip()
                current_tags = set()
                current_desc = ""
                current_body_lines = []

            elif current_block_name is not None:
                # Parse metadata lines (# tags:, # desc:)
                if line.startswith("# tags:"):
                    tags_str = line.replace("# tags:", "").strip()
                    current_tags = {t.strip() for t in tags_str.split(',') if t.strip()}
                elif line.startswith("# desc:"):
                    current_desc = line.replace("# desc:", "").strip()
                elif not line.startswith("# "):
                    # Body content (skip leading metadata comment lines)
                    current_body_lines.append(line)

        # Save final block
        if current_block_name is not None:
            self._save_block(
                current_block_name, topic, current_tags,
                current_desc, '\n'.join(current_body_lines).strip()
            )

    def _save_block(self, name: str, topic: str, tags: Set[str], desc: str, body: str) -> None:
        """
        Validate and save a block.

        Validation rules:
        - Block name: required, non-empty
        - Tags: optional, but if present must be non-empty after splitting
        - Description: optional, but if present must be non-empty
        - Body: optional

        Invalid blocks are skipped with a warning.
        """
        # Validate block name
        if not name or not name.strip():
            print(f"[!] Skipped block with empty name in {topic}", file=sys.stderr)
            return

        name = name.strip()

        # Warn if duplicate name
        if name in self.index_by_name:
            print(f"[!] Duplicate block name '{name}' in {topic}; keeping first occurrence", file=sys.stderr)
            return

        block = KBBlock(
            name=name,
            topic=topic,
            tags=tags,
            description=desc,
            body=body,
        )
        self.blocks.append(block)

    def list_blocks(self) -> str:
        """
        List all blocks grouped by topic.

        Format:
            [topic]

            blockname (tags: tag1, tag2)
              one-line description
        """
        if not self.blocks:
            return "(No blocks loaded.)"

        output = []

        for topic in sorted(self.index_by_topic.keys()):
            output.append(f"\n[{topic}]")
            output.append("")

            for block in sorted(self.index_by_topic[topic], key=lambda b: b.name):
                tags_str = f"tags: {', '.join(sorted(block.tags))}" if block.tags else ""
                output.append(f"{block.name} ({tags_str})")
                if block.description:
                    output.append(f"  {block.description}")

        return "\n".join(output)

    def show_block(self, key: str) -> Optional[str]:
        """
        Retrieve block(s) by key (exact name first, then by tag).

        Returns:
            Formatted block(s), or None if not found.
        """
        results = []

        # Try exact name match first
        if key in self.index_by_name:
            results.append(self.index_by_name[key])
        # Then try tag match
        elif key in self.index_by_tag:
            results.extend(self.index_by_tag[key])
        else:
            return None

        return "\n\n".join(str(block) for block in results)

    def grep_blocks(self, term: str) -> Optional[str]:
        """
        Full-text search across block names, tags, descriptions, and bodies.

        Returns:
            Matching blocks with topic/name header, or None if no matches.
        """
        term_lower = term.lower()
        matches = []

        for block in self.blocks:
            if term_lower in block.searchable_text:
                matches.append(block)

        if not matches:
            return None

        output = []
        for block in sorted(matches, key=lambda b: (b.topic, b.name)):
            output.append(f"[{block.topic}] {block.name}")
            output.append(f"  tags: {', '.join(sorted(block.tags)) if block.tags else '(none)'}")
            output.append(f"  desc: {block.description}")
            output.append("")
            # Show context: first 300 chars of body
            if block.body:
                context = block.body[:300]
                if len(block.body) > 300:
                    context += "..."
                output.append(f"  context: {context}")
            output.append("")

        return "\n".join(output)
