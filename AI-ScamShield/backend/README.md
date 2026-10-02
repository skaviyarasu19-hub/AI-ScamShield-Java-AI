# AI ScamShield - Backend (Spring Boot)

See the root-level README.md for full project documentation.

## Quick start

1. Copy `.env.example` to `.env`, replace `JWT_SECRET` with a unique random
   value of at least 32 characters, and set database credentials if using MySQL.
   Spring Boot imports this file automatically. To create an admin account on
   first startup, also set all three `SEED_ADMIN_*` values.
2. Create the database (or let Hibernate auto-create it):
   ```
   mysql -u root -p < ../database/DATABASE_SETUP.sql
   ```
3. Run:
   ```
   mvn spring-boot:run
   ```
   or run `ScamShieldApplication.java` directly from IntelliJ IDEA / VS Code.
4. The API will be available at `http://localhost:8080`.

No accounts are created with default passwords. Register a user in the app.
To provision an administrator on first startup, set `SEED_ADMIN_USERNAME`,
`SEED_ADMIN_EMAIL`, and `SEED_ADMIN_PASSWORD` in the environment. Set a unique
`JWT_SECRET` of at least 32 random characters before starting the backend.
