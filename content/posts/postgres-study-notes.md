+++
author = "Adam Bouhmad"
title = "Postgres Study Notes"
description = "Postgres Study Notes"
date = "2024-12-09"
categories = ["Postgres", "PostgreSQL", "Product Management", "Data Analytics", "Development", "GoLang"]
tags = ["Development", "golang"]
menu = "main"
featured = ""
featuredalt = ""
featuredpath = ""
linktitle = ""
type = "post"
draft = true
+++

## Chapter 1

- Installed pgAdmin & Postgres via postgresapp.com to get started quickly.
- pgAdmin is pretty neat in that it is
  - Free
  - allows you to see the database system stats
  - allows you to query multiple databases, optionally adding notes for specific queries

## Chapter 2 - Creating your first Database and Table

- SQL is a way to extract knowledge from and define structures for data, drawing relationships between data
  - Table is a structure
  - Amount of tables hints at the data i'll need to analyze, as well as the relationships i can explore amongst the data
- Database builders organize data using separate tables for each main entity to avoid redundant data
  - Example: storing name and dob just once, dont waste db space entering name next to each class, just include the id to draw relationships with
- ANSI SQL Standard defines a set of rules and commands for interacting with rdms. Semicolons at the end of queries is one example for a standard, not all variants respect it
- Best practice to separate databases by projects, as to keep tables with related data together
- Constraints ensure required columns are populated with data, and that we're not duplicating values
  - Example query we wrote:

```sql
CREATE TABLE teachers (
    id bigserial,
    first_name varchar(25),
    last_name varchar(50),
    school varchar(50),
    hire_date date,
    salary numeric
);
```

  - No constraints mean there values aren't required to be populated. We could enforce this app side, but it's important to have defense in depth and enforce constraints on the database side. Chapter 8 covers constraints
  - We separate out each line of the code to make it more readable
  - bigserial is a data type, a special int that increments every time a row is added
- Practiced an INSERT Statement, i.e:

```sql
INSERT INTO teachers(first_name, last_name, school, hire_date, salary)
VALUES('Adam', 'Bouhmad', 'Eastern Technical High School' '2014-05-12', '50000'),
(...) ;
```

- ISO 8601 date format fun: https://xkcd.com/1179/
- Viewing all a table & all rows in pgadmin (option shift v when table is selected)
- Lowercase & underscores for tables & column names is recommended(i.e boundary_sessions)
- CREATE TABLE zoo;
- Database catalogging all animals in our zoo
  - Initially wanted to do zoo_animals as the name, but broadening the name of the database, as we may want to track other items, i.e cost of animals, feed, etc
  - One table to track kinds of animals in collection

```sql
CREATE TABLE current_zoo_animals (
    animal_id int, // This becomes our primary key! Before I had id bigserial included, this is not needed to link the two tables! Just one id column for this table
    species varchar(50)
);
```

  - One table to track specifics on each animal

```sql
CREATE TABLE zoo_animal_details{
    detail_id bigserial
    animal_id int, // This becomes our foreign key, linking the two tables!
    name varchar(50),
    weight_lbs numeric,
    height_inches numeric,
};
```

## Chapter 3 - Beginning Data Exploration With Select

- TABLE <tablename>; does the same thing as SELECT * FROM <tablename>;
  - Example: TABLE teachers;
  - Example: SELECT * FROM teachers;
- Ids of type bigserial will be automatically filled with sequential integers, basically auto-incrementing
- Select specific columns, adding additional commas as needed.

```sql
SELECT first_name, last_name, salary FROM teachers;
```

- ORDER BY <column> ASC/DESC
  - Example: SELECT first_name, last_name, salary FROM teacher ORDER BY salary DESC;
    - Selects the first_name, last_name, and salary columns from the teachers table, ordering the output by the column salary in descending order.
    - ORDER BY <number> DESC basically means you sort by the column number specified(i.e 1st column, 2nd, third, etc)
  - You can pair multiple orders
    - I.e ORDER BY school ASC & hire_date DESC to get a list of, from top to bottom, most recently hired teachers grouped by school
    - Digesting data happens most easily when the result focuses on answering a specific question. Using many orderby clauses will add complexity to the directions of the sorts output. Lead with simplicity and focus on what youre trying to answer
      - Limit the number of columns in your query to the most important, and then run several queries to answer each question
- Use Distinct to find unique ranges of values in a column. Distinct also helps find inconsistencies in Data(i.e dupe data due to wrong spelling of a customer)
  - ie: SELECT DISTINCT school FROM teachers ORDER BY school;
    - Output gives you unique column values for schools, ordered alphabetically by the school name outputted
  - Can specify multiple distinct values, but it'll be the unique pairing of the two values.
    - "Helps us ask questions like, for each x in the table, what are all the y values? For each factory, what are all the chemicals it produces? For each election district, who are all the candidates running for office?
- Use the Where clause to find rows that match a specific value, a range of values, or multiple values supplied by an operator keyword
  - Operator keywords allow us to perform match, comparisons, and logical operations
  - Example:

```sql
SELECT DISTINCT first_name, last_name, school, salary
FROM teachers
WHERE school= 'Eastern Technical Highschool'
ORDER BY first_name DESC;
```

  - != OPERATOR IS NOT ANSI SQL STANDARD, BUT IS AVAILABLE IN POSTGRES AND OTHER DBS
- ILIKE operator used alongside WHERE <column> ILIKE '<value>' is case insensitive, and is not ANSI SQL standard; it's a pgsql implementation
- LIKE & ILIKE search for patterns, so performance on large dbs can be slow. This is where performance can be improved using indexes; we'll learn about how to speed up queries w/indexes in chapt 6
  - Example using AND/OR:

```sql
SELECT first_name, last_name, school, salary
FROM teachers
WHERE school = 'Eastern Technical Highschool'
AND (salary > 100000 OR salary < 60000)
ORDER BY salary DESC
;
```

- Example ILIKE pattern to retrieve all teachers that work or worked at Father Kobe:

```sql
SELECT first_name, last_name, school, salary
FROM teachers
WHERE school ILIKE 'f%ther%'
ORDER BY salary DESC
;
```

- ORDER OF OPERATIONS MATTERS!
  - ORDER BY first_name ASC, school ASC
    - This will order by firstname in ascending order first, and THEN school
  - ORDER BY school ASC first_name ASC
    - This will order by school in ascending order first, and THEN first_name
- ORDER BY is ASC by default!

## Chapter 4

- Performance improvements of using one character datatype over another is negligible in postgres(varchar, char, text); moreso used to single field constraint of data inputted(i.e state postal zip codes MD, WA should only be 2 chars).
- Helpful Tip:
  - When you get a connection to PostgreSQL it is always to a particular database. To access a different database, you must get a new connection.
  - Using \c in psql closes the old connection and acquires a new one, using the specified database and/or credentials.
- Fixed Point is also called arbitrary precision(NUMERIC(precision, scale)). Precision is the maximum number of digits, scale is the maximum subset of those digits allowed to the right of a decimal.
- Floating point is much more imprecise than fixed, as the computer tries to squeeze lots of info into a finite number of bits
- A fixed number of 7000000.00000 could be floating 699999999.880791 as an example
- ANSI compliant: <column_name> timestamp with time zone
  - Equivalent in Postgres: either the above or <column_name> timestamptz

## Chapter 5

- In Postgres, FROM is the import statement, TO is the export statement:

```sql
COPY <table_name>
FROM '<file path>'
WITH (FORMAT <csv | json | etc>, HEADER, DELIMITER '<any delimiter used between values, i.e | >');
```

```sql
COPY <table_name>
TO '<file path>'
WITH (FORMAT <csv | json | etc>, HEADER, DELIMITER '<any delimiter to be used between values, i.e | >');
```

- Think about the data types you should use for your data! Need a datatype that stores a number that exceeds 2.1b? Dont use int(big int is better here!! Runescape used ints as an example and forced people to use items as a store of value) Postal service codes may have leading zeroes, ints would remove the leading zeroes!!
- Visually scan the data you imported to make sure all is well(maybe use a limit when selecting on the tables)
- If you have a CSV that has columns that your table does not(you can exclude it by explicitly defining all the columns in the CSV you want to import):

```sql
COPY county_population_2019 (county_name, state_name)
FROM '/Users/adambouhmad/Downloads/us_counties_pop_est_2019.csv'
WITH (FORMAT CSV, HEADER);
```

- Export particular columns:

```sql
COPY <table_name>(<column1, column2, ...>)
TO '<file path>'
WITH (FORMAT <csv | json | etc>, HEADER, DELIMITER '<any delimiter to be used between values, i.e | >');
```

- Export query results:

```sql
COPY (
<Valid Query>
)
TO '<file path>'
WITH (FORMAT <csv | json | etc>, HEADER, DELIMITER '<any delimiter to be used between values, i.e | >');
```

- SELECT 1 + 1 will show you the value in an unknown column. You can display a column name using AS:

```sql
SELECT 1 + 1 AS result;
SELECT *, births_2019 - deaths_2019 AS natural_increase FROM county_population_2019
ORDER BY natural_increase ASC;
```

- Double colon can CAST(CAST IS ANSI SQL standard)

## Chapter 7

- Joins allow us to link rows in one table to rows in other table(s)
- Joins link data in a able to another in a DB using a boolean value expression in the ON clause
  - I.E if the ON clause evaluates to true,, there's a join
  - (could be SELECT * FROM table a JOIN table b ON tablea.key_column = table_b.foreign_key_column)
- A Primary Key is a column or collection of columns who's values uniquely identify each row in a table
  - Columns/Collection of columns identified as primary keys can not have missing values
  - Columns/Collection of columns must have unique values for each row
- "Use a full outer join in SQL when you want to retrieve all records from both tables involved in the join, regardless of whether there is a matching record in the other table; essentially, you need to see all data from both tables, including unmatched rows from either side, which is useful for scenarios like merging data from two tables while preserving all records, identifying missing data, or comparing data between two sources to find discrepancies."
- JOIN & INNER JOIN are the same. INNER is the default join type for JOIN, so when you write JOIN the parser actually writes INNER JOIN.
- Use JOIN when working with well-structured, well-maintained datasets and you need to find rows that exist in all the tables you're joining
- You can reduce redundant output and simplify query syntax by substituting USING clause in place of the ON clause if the columns in a join are identical
- With LEFT or RIGHT joins, they return all rows from one table and, when a row with a matching value in the other table exists, values from that row are included in the results, otherwise, no values from the other table are displayed
- (Left Outer join is the same as Left Join, in Postgres its just a left join)
- Inner Joins are mostly used, followed by left joins:
  - https://www.reddit.com/r/SQL/comments/s39gy6/most_used_join_operations/
- Cross joins are not good for performance so are barely used
- FULL OUTER JOIN will show you rows from both tables specified regardless of whether they match. Not used often relative to Inner & LEFT/RIGHT JOINS
- A Cartesian product is the set of all possible ordered pairs formed by combining each element of one set with each element of another set. CROSS JOINS give you a cartesian product based on the columns provided. No matches are found between key columns, so there's no need to provide an on clause.
- NOT RECOMMENDED FOR LARGE TABLES - 2 tables w/250k records ea will produce a cartesian product of 62.5billion rows
- Doing a JOIN and specifying WHERE <table>.<column_name> IS NULL is considered an anti join. This can be helpful for spotchecking rows with missing values and fixing this as needed in your dataset.
- The art of joining tables involves understanding how the db was designed(i.e is a table's relationship 1-1, 1-many, or many-many)
- 1-1 Examples:
  - Joining two tables with state-by-state census data. Both tables have 51 rows(one for each state + DC).
    - One Table contains household income data
    - One Table contains educational attainment
  - We'd join these tables on a key like State Name, or State abbreviation, or geography code, as an example
- 1-Many Examples:
  - Joining two tables with automotive data
    - One Table contains manufacturer data, with a column for each of the manufacturers
    - One Table with model names
  - When doing a LEFT JOIN, table 1 will have 1 manufacturer to MANY models(Model3, Model Y, etc)
- Many-Many Examples:
  - Third table is usually involved
    - Think about a baseball league, with a player assigned to multiple positions, and each position can be played by multiple players
      - Players Table
      - Positions Table
      - Player Positions
        - Two columns that support the many-to-many relationship
          - ID from players table, ID from positions table
- Good to add the table name infront of each column we're querying to avoid ambiguous errors where the DB doesn't know which table we're selecting on during a JOIN

```sql
SELECT district_2020.id, district_2020.school_2020, district_2035.school_2035 FROM district_2020
LEFT JOIN district_2035 ON district_2020.id = district_2035.id
```

- Table aliases greatly help with readability when writing queries:

```sql
SELECT d_2020.id, d_2020.school_2020, d_2035.school_2035
FROM district_2020 AS d_2020 LEFT JOIN district_2035 AS d_2035
ON d_2020.id = d_2035.id
```

- (here I'm declaring the alias d_2020 and d_2035 in the FROM statement, enabling me to use those aliases in the rest of my query)
- Typically no hard limit on the number of tables you can join in a single query
