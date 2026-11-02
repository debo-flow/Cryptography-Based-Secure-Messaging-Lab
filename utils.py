"""
Application Utilities & Error Handling Layer.
"""
import streamlit as st
import functools
import logging
from typing import Callable, Any

logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

def error_handler(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Error in {func.__name__}: {str(e)}")
            st.error("An unexpected error occurred. Please check your inputs and try again.")
    return wrapper

def render_coming_soon(section_name: str) -> None:
    st.title(section_name)
    st.divider()
    st.info(f"🚀 **Coming in Future Milestones**\n\nThe `{section_name}` module is currently under development as per the project roadmap.", icon="🔒")
    st.progress(0, text="Implementation Status: 0%")

def create_metric_card(title: str, value: str, delta: str = None) -> None:
    st.metric(label=title, value=value, delta=delta)
