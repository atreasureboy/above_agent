"""DEVOPS_driver — CLI entry point with GUI and Agent modes."""
import sys

if len(sys.argv) > 1:
    cmd = sys.argv[1]
    if cmd == "gui":
        from src.gui.app import AgentChatWindow
        AgentChatWindow().run()
        sys.exit(0)
    elif cmd == "agent":
        from src.agent_cli import main as agent_main
        sys.exit(agent_main())
    # Fall through to normal CLI (existing main)

from src.main import main
sys.exit(main())
