import { App, applyDocumentTheme, applyHostStyleVariables, type McpUiHostContext } from '@modelcontextprotocol/ext-apps';

const app = new App({ name: 'sudo-relay', version: '0.1.0' }, { availableDisplayModes: ['inline'] });
function applyContext(context: McpUiHostContext): void {
  if (context.theme) applyDocumentTheme(context.theme);
  if (context.styles?.variables) applyHostStyleVariables(context.styles.variables);
}
app.onhostcontextchanged = applyContext;
void app.connect().then(() => {
  const context = app.getHostContext();
  if (context) applyContext(context);
}).catch(() => {
  const status = document.querySelector('#status');
  if (status) status.textContent = 'Chat display unavailable. Check execution status; do not assume approval or retry the command.';
});
