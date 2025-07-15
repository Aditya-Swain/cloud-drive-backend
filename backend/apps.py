from django.apps import AppConfig


class BackendConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "backend"
    
    def ready(self): 
        print("Backend app is ready")   # Import signals so they are connected when the app is ready
        import backend.signals

