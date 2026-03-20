# =============================================================================
# SQL Injection Detection Test Cases
# Combined positive (vulnerable) and negative (safe) test cases for all 8 rules
# =============================================================================

# ---------------------------------------------------------------------------
# Rule 1: sql-injection-fstring — f-string in execute()
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
db.execute(f"INSERT INTO logs VALUES ({msg})")
conn.execute(f"DELETE FROM users WHERE name = '{name}'")

# NEGATIVE: should NOT trigger
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users")
print(f"SELECT * FROM users WHERE id = {user_id}")


# ---------------------------------------------------------------------------
# Rule 2: sql-injection-format — .format() in execute()
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
db.execute("INSERT INTO {} VALUES ({})".format(table, value))
cursor.execute("DELETE FROM users WHERE name = '{}'".format(name))

# NEGATIVE: should NOT trigger
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users")
log.info("Query: {}".format(query))


# ---------------------------------------------------------------------------
# Rule 3: sql-injection-percent — %-formatting in execute()
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
db.execute("INSERT INTO %s VALUES (%s)" % (table, value))
cursor.execute("DELETE FROM users WHERE name = '%s'" % name)

# NEGATIVE: should NOT trigger
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users")
print("Query: %s" % query)


# ---------------------------------------------------------------------------
# Rule 4: sql-injection-concat — string concatenation in execute()
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
db.execute("INSERT INTO " + table + " VALUES (1)")
cursor.execute("DELETE FROM users WHERE name = '" + name + "'")

# NEGATIVE: should NOT trigger
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users")
result = "SELECT " + column


# ---------------------------------------------------------------------------
# Rule 5: sql-injection-django-raw — Django .objects.raw() with dynamic query
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
User.objects.raw(f"SELECT * FROM auth_user WHERE id = {user_id}")
Post.objects.raw("SELECT * FROM blog_post WHERE author = '{}'".format(author))

# NEGATIVE: should NOT trigger
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
User.objects.raw("SELECT * FROM auth_user")


# ---------------------------------------------------------------------------
# Rule 6: sql-injection-django-extra — Django .extra() with dynamic where
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
queryset.extra(where=[f"name = '{name}'"])
qs.extra(where=["id = {}".format(user_id)])

# NEGATIVE: should NOT trigger
queryset.extra(where=["name = %s"], params=[name])
queryset.filter(name=name)


# ---------------------------------------------------------------------------
# Rule 7: sql-injection-sqlalchemy-text — SQLAlchemy text() with f-string
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
db.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))
session.execute(text("SELECT * FROM users WHERE name = '{}'".format(name)))

# NEGATIVE: should NOT trigger
db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
db.execute(text("SELECT * FROM users"))


# ---------------------------------------------------------------------------
# Rule 8: sql-injection-psycopg2-format — .format() on variable in execute()
# ---------------------------------------------------------------------------

# POSITIVE: should trigger
cursor.execute(query.format(user_id))
cursor.execute(sql.format(table=table_name, id=user_id))
db.execute(base_query.format(name))

# NEGATIVE: should NOT trigger
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute(query, (param,))
result = query.format(user_id)
