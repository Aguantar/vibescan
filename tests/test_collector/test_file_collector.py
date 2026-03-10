"""Tests for File Collector (Track A: text files, Track B: all files)."""

from __future__ import annotations

from pathlib import Path

from vibescan.collector.file_collector import collect


class TestTextFileCollection:
    """Track A: text file collection with content reading."""

    def test_collects_python_file(self, tmp_path: Path):
        (tmp_path / "main.py").write_text("print('hello')")
        ctx = collect(tmp_path)
        assert len(ctx.text_files) == 1
        assert ctx.text_files[0].path == "main.py"
        assert ctx.text_files[0].content == "print('hello')"

    def test_collects_js_and_json(self, tmp_path: Path):
        (tmp_path / "app.js").write_text("const x = 1;")
        (tmp_path / "package.json").write_text('{"name":"test"}')
        ctx = collect(tmp_path)
        paths = {tf.path for tf in ctx.text_files}
        assert paths == {"app.js", "package.json"}

    def test_collects_extensionless_known_names(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM node:18")
        (tmp_path / "Makefile").write_text("all:\n\techo hi")
        ctx = collect(tmp_path)
        paths = {tf.path for tf in ctx.text_files}
        assert "Dockerfile" in paths
        assert "Makefile" in paths

    def test_skips_binary_file(self, tmp_path: Path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        ctx = collect(tmp_path)
        assert len(ctx.text_files) == 0
        assert "image.png" in ctx.all_files

    def test_skips_large_file(self, tmp_path: Path):
        big = tmp_path / "huge.py"
        big.write_text("x = 1\n" * 1_000_000)  # ~6MB
        ctx = collect(tmp_path)
        assert len(ctx.text_files) == 0
        assert "huge.py" in ctx.skipped_files

    def test_skips_utf8_decode_error(self, tmp_path: Path):
        bad = tmp_path / "bad.py"
        bad.write_bytes(b"\x80\x81\x82\x83")
        ctx = collect(tmp_path)
        assert len(ctx.text_files) == 0
        assert "bad.py" in ctx.skipped_files

    def test_nested_directory_collection(self, tmp_path: Path):
        sub = tmp_path / "src" / "lib"
        sub.mkdir(parents=True)
        (sub / "util.py").write_text("def f(): pass")
        ctx = collect(tmp_path)
        assert ctx.text_files[0].path == "src/lib/util.py"


class TestAllFileCollection:
    """Track B: all files including binaries."""

    def test_includes_all_file_types(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("pass")
        (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02")
        (tmp_path / "photo.jpg").write_bytes(b"\xff\xd8\xff")
        ctx = collect(tmp_path)
        assert len(ctx.all_files) == 3

    def test_relative_paths(self, tmp_path: Path):
        sub = tmp_path / "deep" / "nested"
        sub.mkdir(parents=True)
        (sub / "file.txt").write_text("hi")
        ctx = collect(tmp_path)
        assert "deep/nested/file.txt" in ctx.all_files


class TestExcludedDirectories:
    def test_skips_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("module.exports = {}")
        ctx = collect(tmp_path)
        assert len(ctx.all_files) == 0

    def test_skips_git_dir(self, tmp_path: Path):
        git = tmp_path / ".git" / "objects"
        git.mkdir(parents=True)
        (git / "abc123").write_bytes(b"\x00")
        ctx = collect(tmp_path)
        assert len(ctx.all_files) == 0

    def test_skips_pycache(self, tmp_path: Path):
        pc = tmp_path / "__pycache__"
        pc.mkdir()
        (pc / "mod.cpython-312.pyc").write_bytes(b"\x00")
        ctx = collect(tmp_path)
        assert len(ctx.all_files) == 0

    def test_skips_egg_info(self, tmp_path: Path):
        egg = tmp_path / "mypackage.egg-info"
        egg.mkdir()
        (egg / "PKG-INFO").write_text("Name: mypackage")
        ctx = collect(tmp_path)
        assert len(ctx.all_files) == 0

    def test_does_not_skip_normal_dirs(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("pass")
        ctx = collect(tmp_path)
        assert "src/main.py" in ctx.all_files


class TestSymlinkHandling:
    def test_skips_symlinked_file(self, tmp_path: Path):
        real = tmp_path / "real.py"
        real.write_text("pass")
        link = tmp_path / "link.py"
        link.symlink_to(real)
        ctx = collect(tmp_path)
        assert "real.py" in ctx.all_files
        assert "link.py" not in ctx.all_files

    def test_skips_symlinked_dir(self, tmp_path: Path):
        real_dir = tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.py").write_text("pass")
        link_dir = tmp_path / "link_dir"
        link_dir.symlink_to(real_dir)
        ctx = collect(tmp_path)
        paths = set(ctx.all_files)
        assert "real_dir/file.py" in paths
        assert "link_dir/file.py" not in paths
