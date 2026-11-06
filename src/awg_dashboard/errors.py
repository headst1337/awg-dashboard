class AwgDashboardError(Exception):
    pass


class ValidationError(AwgDashboardError):
    pass


class DockerRuntimeError(AwgDashboardError):
    pass


class NotInstalledError(AwgDashboardError):
    pass


class ConflictError(AwgDashboardError):
    pass


class ClientNotFoundError(AwgDashboardError):
    pass


class StateStoreError(AwgDashboardError):
    pass


class ReconciliationError(AwgDashboardError):
    pass
