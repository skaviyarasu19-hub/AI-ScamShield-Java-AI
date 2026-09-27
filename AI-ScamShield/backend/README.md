# AI ScamShield - Backend (Spring Boot)

See the root-level README.md for full project documentation.

## Quick start

1. Copy `.env.example` to `.env` and fill in your MySQL credentials (or set the
   same variables as real environment variables / in your IDE run configuration).
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

Default seeded accounts (created automatically on first run):
- Admin: `admin` / `Admin@123`
- Test user: `testuser` / `Test@123`
