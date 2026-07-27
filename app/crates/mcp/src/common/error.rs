use rmcp::ErrorData as McpError;

pub(crate) fn mcp_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}
