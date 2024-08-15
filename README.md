# AspNet-to-Auth0 Migration

Tool to export AspNet Identity Users & Roles to Auth0 platform.

# How To

1. Prepare csv files and place inside `data` dir (check the templates).

2. Create a `.env` file with your Auth0 credentials.

3. Run the script

```bash
# export users
python main.py --users

# export roles
python main.py --roles
```
