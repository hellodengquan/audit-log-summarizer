"""顶层入口脚本：`python main.py ...` 等价于 `python -m audit_summarizer.cli ...`。"""

import sys
from audit_summarizer.cli import main

if __name__ == "__main__":
    sys.exit(main())
