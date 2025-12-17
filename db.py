import os
import mysql.connector


def connect_db():
    """
    Low-level MySQL connection used outside SQLAlchemy, aligned with the provided Aiven URL.
    Honors environment variables when present; otherwise defaults to the given Aiven instance.

    Aiven URL reference:
    mysql://avnadmin:AVNS_C7NwOivkv-f-qjPwdY5@mysql-b292672-vireakrom69-33eb.f.aivencloud.com:25481/defaultdb?ssl-mode=REQUIRED
    """
    host = os.environ.get("DB_HOST", "mysql-b292672-vireakrom69-33eb.f.aivencloud.com")
    user = os.environ.get("DB_USER", "avnadmin")
    password = os.environ.get("DB_PASSWORD", "AVNS_C7NwOivkv-f-qjPwdY5")
    database = os.environ.get("DB_NAME", "defaultdb")
    port = int(os.environ.get("DB_PORT", 25481))

    # Enforce SSL like `ssl-mode=REQUIRED` in the URL.
    # For stricter verification with custom CA, set DB_SSL_CA to a path.
    ssl_ca = os.environ.get("DB_SSL_CA")
    ssl_kwargs = {}
    if ssl_ca:
        ssl_kwargs["ssl_ca"] = ssl_ca
    else:
        # Without a CA, require TLS without cert verification.
        # mysql-connector uses tls by default if ssl_disabled is False
        ssl_kwargs["ssl_disabled"] = False

    return mysql.connector.connect(
        host=host,
        user=user,
        password=password,
        database=database,
        port=port,
        **ssl_kwargs
    )
