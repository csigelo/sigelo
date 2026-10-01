// Launcher for the plugin's .mcp.json. node realpaths its main module, so this relative import
// reaches integrations/mcp/server.mjs in the checkout even when this directory is a symlink
// (~/.claude/skills/sigelo -> <checkout>/integrations/claude-code/skills/sigelo).
import '../../../mcp/server.mjs';
