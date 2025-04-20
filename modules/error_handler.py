from .logger import logger
from .config import config
import traceback

class ErrorHandler:
    def __init__(self):
        self.error_count = 0
        self.max_errors = 10
        
    def handle_error(self, error, context=None):
        """Handle a non-critical error"""
        self.error_count += 1
        if context:
            logger.error(f"{context}: {str(error)}")
        else:
            logger.error(str(error))
            
        if self.error_count >= self.max_errors:
            logger.warning("Maximum error count reached. Switching to simulation mode.")
            config.simulation_mode = True
            self.error_count = 0
            
    def handle_critical_error(self, error, context=None):
        """Handle a critical error that might require application restart"""
        if context:
            logger.critical(f"CRITICAL ERROR - {context}: {str(error)}")
        else:
            logger.critical(f"CRITICAL ERROR: {str(error)}")
            
        # Log the full traceback
        logger.critical(traceback.format_exc())
        
        # Switch to simulation mode
        config.simulation_mode = True
        logger.info("Switched to simulation mode due to critical error")
        
    def reset_error_count(self):
        """Reset the error counter"""
        self.error_count = 0

# Create global error handler instance
error_handler = ErrorHandler() 