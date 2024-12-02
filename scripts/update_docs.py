import click
from pathlib import Path
import sys
import re
# Add the project root to Python path so we can import the CLI
project_root = Path(__file__).parent.parent

from nabit.bin.cli import main

readme_path = project_root / 'README.md'


def get_new_readme_text():
    ctx = click.Context(main)
    
    # Get help text for the main command
    help_text = f'\n```\n{ctx.get_help()}\n```\n\n'
    
    # Get help text for all commands
    for cmd_name, cmd in sorted(main.commands.items()):
        help_text += f"""\
### {cmd_name}
```
{click.Context(cmd, parent=ctx).get_help()}
```\n\n"""
    
    # Update the usage section in README.md
    readme_path = project_root / 'README.md'
    readme_content = readme_path.read_text()
    readme_content = re.sub(
        r'(<!-- usage start -->).*(<!-- usage end -->)', 
        r'\1' + help_text + r'\2', 
        readme_content, 
        flags=re.DOTALL
    )

    return readme_content

def update_readme():
    """Update README.md with latest command help"""
    readme_path.write_text(get_new_readme_text())
    print("README.md updated")

if __name__ == '__main__':
    update_readme() 