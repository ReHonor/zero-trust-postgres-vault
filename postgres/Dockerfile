FROM postgres:16

# pgaudit is packaged by the PostgreSQL project's apt repo that the official image already uses
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-16-pgaudit \
 && rm -rf /var/lib/apt/lists/*

COPY pg-entrypoint.sh /usr/local/bin/pg-entrypoint.sh
RUN chmod +x /usr/local/bin/pg-entrypoint.sh

ENTRYPOINT ["pg-entrypoint.sh"]
CMD ["postgres"]
