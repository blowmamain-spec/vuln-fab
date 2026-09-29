"""Laravel migrations and Eloquent models -> schema (WP-7.1)."""
# ruff: noqa: E501

from __future__ import annotations

from pathlib import Path

from vulnfab.core.loader import Repo
from vulnfab.core.models import Confidence
from vulnfab.plugins.laravel import LaravelPlugin
from vulnfab.plugins.laravel.migrations import MigrationBuilder, pluralize, snake, table_for_class

USERS = """<?php
use Illuminate\\Database\\Migrations\\Migration;
use Illuminate\\Support\\Facades\\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('email')->unique();
            $table->string('password');
            $table->rememberToken();
            $table->timestamps();
        });
    }
    public function down(): void {
        Schema::dropIfExists('users');
    }
};
"""

POSTS = """<?php
return new class extends Migration {
    public function up(): void {
        Schema::create('posts', function (Blueprint $table) {
            $table->id();
            $table->string('title', 100)->nullable();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('editor_id')->nullable()->constrained('users');
            $table->text('api_token');
            $table->morphs('taggable');
            $table->softDeletes();
        });
    }
};
"""

ALTER = """<?php
return new class extends Migration {
    public function up(): void {
        Schema::table('posts', function (Blueprint $table) {
            $table->string('slug')->unique();
            $table->dropColumn('api_token');
            $table->renameColumn('title', 'headline');
            $table->foreignIdFor(Category::class);
        });
        Schema::table('users', function (Blueprint $table) {
            $table->boolean('is_admin')->default(false);
        });
    }
    public function down(): void {
        Schema::table('posts', function (Blueprint $table) {
            $table->dropColumn('slug');
        });
    }
};
"""


def build(*files: tuple[str, str]) -> MigrationBuilder:
    b = MigrationBuilder()
    for path, text in files:
        b.apply_file(path, text)
    return b


def test_naming_helpers() -> None:
    assert snake("BlogPost") == "blog_post"
    assert pluralize("category") == "categories" and pluralize("box") == "boxes"
    assert table_for_class("BlogPost") == "blog_posts"


def test_create_columns_types_and_flags() -> None:
    users = build(("m1.php", USERS)).model.tables["db.users"]
    names = [c.name for c in users.columns]
    assert names == ["id", "email", "password", "remember_token", "created_at", "updated_at"]
    email = users.columns[1]
    assert email.unique and email.type == "string" and not email.nullable
    assert users.columns[2].sensitive_hint and users.columns[3].sensitive_hint
    assert not users.columns[1].sensitive_hint


def test_down_method_is_ignored() -> None:
    assert "db.users" in build(("m1.php", USERS)).model.tables  # dropIfExists lives in down()


def test_foreign_keys_and_morphs() -> None:
    posts = build(("m1.php", USERS), ("m2.php", POSTS)).model.tables["db.posts"]
    cols = {c.name: c for c in posts.columns}
    assert cols["user_id"].references == "users"
    assert cols["editor_id"].references == "users" and cols["editor_id"].nullable
    assert cols["title"].nullable
    assert "taggable_id" in cols and "taggable_type" in cols and "deleted_at" in cols
    assert cols["api_token"].sensitive_hint


def test_alter_table_final_state() -> None:
    model = build(("m1.php", USERS), ("m2.php", POSTS), ("m3.php", ALTER)).model
    posts = {c.name: c for c in model.tables["db.posts"].columns}
    assert "api_token" not in posts and "title" not in posts and "headline" in posts
    assert posts["slug"].unique
    assert posts["category_id"].references == "categories"
    assert "is_admin" in {c.name for c in model.tables["db.users"].columns}


def test_dynamic_table_name_is_unresolved() -> None:
    text = "<?php\nreturn new class {\n public function up() {\n  Schema::create($name, function ($t) {});\n }\n};\n"
    model = build(("m.php", text)).model
    assert model.unresolved and model.unresolved[0].kind == "dynamic_table"


def test_alter_of_unknown_table_creates_external_stub() -> None:
    model = build(("m.php", ALTER)).model
    assert model.tables["db.users"].external


def test_plugin_detect_and_models(tmp_path: Path) -> None:
    files = {
        "artisan": "#!/usr/bin/env php\n",
        "database/migrations/2024_01_01_000000_users.php": USERS,
        "database/migrations/2024_01_02_000000_posts.php": POSTS,
        "app/Models/Post.php": (
            "<?php\nnamespace App\\Models;\nuse Illuminate\\Database\\Eloquent\\Model;\n"
            "class Post extends Model {\n"
            "    protected $guarded = [];\n"
            "    protected $hidden = ['api_token'];\n"
            "    public function user() { return $this->belongsTo(User::class); }\n"
            "}\n"
        ),
        "app/Models/Ghost.php": "<?php\nclass Ghost extends Model {}\n",
    }
    for rel, text in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    repo = Repo(tmp_path)
    plugin = LaravelPlugin()
    assert plugin.detect(repo) is Confidence.HIGH
    model = plugin.extract_schema(repo)
    assert model is not None
    posts = model.tables["db.posts"]
    assert posts.extras["model"] == "Post"
    assert posts.extras["guarded"] == [] and posts.extras["hidden"] == ["api_token"]
    assert posts.extras["relations"] == [("belongsTo", "user", "User")]
    assert any(u.kind == "model_without_migration" for u in model.unresolved)


def test_detect_composer_dependency(tmp_path: Path) -> None:
    (tmp_path / "composer.json").write_text('{"require": {"laravel/framework": "^11.0"}}')
    assert LaravelPlugin().detect(Repo(tmp_path)) is Confidence.HIGH
    (tmp_path / "composer.json").write_text('{"require": {"monolog/monolog": "^3"}}')
    assert LaravelPlugin().detect(Repo(tmp_path)) is Confidence.LOW
