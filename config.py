from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Neo4j
    neo4j_uri: str = "neo4j://127.0.0.1:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "meridian123"
    neo4j_database: str = "cybergraph"

    # Simulator
    sim_normal_events: int = 5000
    sim_anomaly_events: int = 500
    sim_seed: int = 42

    # Autoencoder
    ae_hidden_dims: list[int] = [64, 32, 16]
    ae_epochs: int = 50
    ae_batch_size: int = 64
    ae_learning_rate: float = 1e-3
    ae_anomaly_threshold: float = 0.95   # percentile of reconstruction error

    # Output
    output_dir: str = "data/findings"

    @property
    def neo4j_auth(self) -> tuple[str, str]:
        return self.neo4j_user, self.neo4j_password


settings = Settings()
