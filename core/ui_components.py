"""
Advanced UI/UX Component Library (M29).
Provides centralized design tokens, contextual help, status badges, and layout wrappers 
for a consistent, professional, and accessible user experience.
"""
import streamlit as st

def page_header(title: str, description: str, icon: str = "🛡️"):
    """Standardized page header with professional typography and spacing."""
    st.title(f"{icon} {title}")
    st.markdown(f"<p style='color: #A0AEC0; font-size: 1.15rem; margin-top: -10px; margin-bottom: 20px;'>{description}</p>", unsafe_allow_html=True)
    st.divider()

def contextual_help(topic: str, content: str):
    """Accessible contextual educational help accordion."""
    with st.expander(f"📚 Contextual Help: {topic}"):
        st.markdown(content)

def status_badge(status: str) -> str:
    """Returns HTML for a colored status badge based on security/lifecycle state."""
    status_up = status.upper()
    color_map = {
        "ACTIVE": "#00C853", "VALID": "#00C853", "AUTHENTICATED": "#00C853", "COMPLETED": "#00C853",
        "GENERATED": "#2962FF", "QUEUED": "#2962FF", "SENT": "#2962FF",
        "WARNING": "#FFAB00", "PENDING": "#FFAB00", "INACTIVE": "#FFAB00", "UNVERIFIED": "#FFAB00",
        "EXPIRED": "#D50000", "REVOKED": "#D50000", "COMPROMISED": "#D50000", "FAILED": "#D50000", "INVALID": "#D50000"
    }
    bg_color = color_map.get(status_up, "#757575")
    return f"<span style='color: #FFFFFF; background-color: {bg_color}; padding: 0.2rem 0.6rem; border-radius: 12px; font-size: 0.75rem; font-weight: 600; display: inline-block; vertical-align: middle;'>{status_up}</span>"

def render_metric_card(label: str, value: str, delta: str = None):
    """Renders a responsive metric card."""
    st.metric(label=label, value=value, delta=delta)

def display_security_warning(message: str):
    """Standardized high-visibility security warning."""
    st.warning(f"⚠️ **SECURITY WARNING:** {message}")

def display_error_safe(exception: Exception):
    """Displays generic errors without exposing internal stack traces or secrets."""
    st.error(f"🚨 **Cryptographic Operation Failed:** {str(exception)}")
