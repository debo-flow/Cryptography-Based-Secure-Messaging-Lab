"""
Application Utilities & Error Handling Layer.
Provides reusable functions for UI layout and graceful error management.
"""

import streamlit as st
import functools
import logging
from typing import Callable, Any

# Configure standard logging to avoid exposing sensitive info directly to UI
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def error_handler(func: Callable) -> Callable:
    """
    Decorator for centralized, graceful exception handling.
    Catches errors, logs them safely, and displays user-friendly UI messages 
    without exposing stack traces or sensitive data.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            st.error("An unexpected error occurred. Please check your inputs and try again.")
    return wrapper

def render_coming_soon(section_name: str) -> None:
    """
    Renders a standardized placeholder for unimplemented features.
    """
    st.title(section_name)
    st.divider()
    st.info(f"🚀 **Coming in Future Milestones**\n\nThe `{section_name}` module is currently under development as per the project roadmap.", icon="🔒")
    st.progress(0, text="Implementation Status: 0%")

def create_metric_card(title: str, value: str, delta: str = None) -> None:
    """
    Renders a stylized metric card for dashboards.
    """
    st.metric(label=title, value=value, delta=delta)
