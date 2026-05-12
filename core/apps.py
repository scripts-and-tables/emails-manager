from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'

    def ready(self) -> None:
        # Importing the signals module registers the @receiver handlers as a
        # side-effect; the F401-suppressed import is the wiring.
        from . import signals  # noqa: F401
