package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/letsencrypt/boulder/features"
)

// MultiInserter makes it easy to construct a
// `INSERT INTO table (...) VALUES ... RETURNING id;`
// query which inserts multiple rows into the same table. It can also execute
// the resulting query.
type MultiInserter struct {
	// These are validated by the constructor as containing only characters
	// that are allowed in an unquoted identifier.
	// https://mariadb.com/kb/en/identifier-names/#unquoted
	table           string
	fields          []string
	returningColumn string

	values [][]interface{}
}

// NewMultiInserter creates a new MultiInserter, checking for reasonable table
// name and list of fields. returningColumn is the name of a column to be used
// in a `RETURNING xyz` clause at the end. If it is empty, no `RETURNING xyz`
// clause is used. If returningColumn is present, it must refer to a column
// that can be parsed into an int64.
// Safety: `table`, `fields`, and `returningColumn` must contain only strings
// that are known at compile time. They must not contain user-controlled
// strings.
func NewMultiInserter(table string, fields []string, returningColumn string) (*MultiInserter, error) {
	if len(table) == 0 || len(fields) == 0 {
		return nil, fmt.Errorf("empty table name or fields list")
	}

	err := validMariaDBUnquotedIdentifier(table)
	if err != nil {
		return nil, err
	}
	for _, field := range fields {
		err := validMariaDBUnquotedIdentifier(field)
		if err != nil {
			return nil, err
		}
	}
	if returningColumn != "" {
		err := validMariaDBUnquotedIdentifier(returningColumn)
		if err != nil {
			return nil, err
		}
	}

	return &MultiInserter{
		table:           table,
		fields:          fields,
		returningColumn: returningColumn,
		values:          make([][]interface{}, 0),
	}, nil
}

// Add registers another row to be included in the Insert query.
func (mi *MultiInserter) Add(row []interface{}) error {
	if len(row) != len(mi.fields) {
		return fmt.Errorf("field count mismatch, got %d, expected %d", len(row), len(mi.fields))
	}
	mi.values = append(mi.values, row)
	return nil
}

// query returns the formatted query string, and the slice of arguments for
// for borp to use in place of the query's question marks. Currently only
// used by .singleStatementInsert(), below.
func (mi *MultiInserter) query() (string, []interface{}) {
	var questionsBuf strings.Builder
	var queryArgs []interface{}
	for _, row := range mi.values {
		// Safety: We are interpolating a string that will be used in a SQL
		// query, but we constructed that string in this function and know it
		// consists only of question marks joined with commas.
		fmt.Fprintf(&questionsBuf, "(%s),", QuestionMarks(len(mi.fields)))
		queryArgs = append(queryArgs, row...)
	}

	questions := strings.TrimRight(questionsBuf.String(), ",")

	// Safety: we are interpolating `mi.returningColumn` into an SQL query. We
	// know it is a valid unquoted identifier in MariaDB because we verified
	// that in the constructor.
	returning := ""
	if mi.returningColumn != "" {
		if features.Get().UseMySQL {
			// We shouldn't get here, this is going to not be compatible
			// with MySQL
			panic("Incompatible with MySQL")
		}
		returning = fmt.Sprintf(" RETURNING %s", mi.returningColumn)
	}
	// Safety: we are interpolating `mi.table` and `mi.fields` into an SQL
	// query. We know they contain, respectively, a valid unquoted identifier
	// and a slice of valid unquoted identifiers because we verified that in
	// the constructor. We know the query overall has valid syntax because we
	// generate it entirely within this function.
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES %s%s", mi.table, strings.Join(mi.fields, ","), questions, returning)

	return query, queryArgs
}

// The MariaDB-implementation of Insert makes use of the MariaDB RETURNING... extension
// to do all the inserts in a single transaction for efficiency.
func (mi *MultiInserter) singleStatementInsert(ctx context.Context, queryer Queryer) ([]int64, error) {
	query, queryArgs := mi.query()
	rows, err := queryer.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, err
	}

	ids := make([]int64, 0, len(mi.values))
	if mi.returningColumn != "" {
		for rows.Next() {
			var id int64
			err = rows.Scan(&id)
			if err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
	}

	// Hack: sometimes in unittests we make a mock Queryer that returns a nil
	// `*sql.Rows`. A nil `*sql.Rows` is not actually valid— calling `Close()`
	// on it will panic— but here we choose to treat it like an empty list,
	// and skip calling `Close()` to avoid the panic.
	if rows != nil {
		err = rows.Close()
		if err != nil {
			return nil, err
		}
	}

	return ids, nil
}

// The MySQL-compatible implementation of Insert loops over the inputs, to SELECT
// out the LAST_INSERT_ID for each as it goes into the database.
func (mi *MultiInserter) mysqlInsert(ctx context.Context, tx OneQueryer) ([]int64, error) {
	results := make([]int64, 0, len(mi.values))
	for _, queryArgs := range mi.values {
		query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", mi.table, strings.Join(mi.fields, ","), QuestionMarks(len(mi.fields)))
		rows, err := tx.QueryContext(ctx, query, queryArgs...)
		if err != nil {
			return nil, err
		}
		if rows != nil {
			err = rows.Close()
			if err != nil {
				return nil, err
			}
		}

		if mi.returningColumn != "" {
			var id int64
			err = tx.SelectOne(ctx, &id, "SELECT LAST_INSERT_ID();")
			if err != nil {
				return nil, err
			}
			results = append(results, id)
		}
	}
	return results, nil
}

// Insert inserts all the collected rows into the database represented by
// `queryer`. If a non-empty returningColumn was provided, then it returns
// the list of values from that column returned by the query.
func (mi *MultiInserter) Insert(ctx context.Context, tx OneQueryer) ([]int64, error) {
	// If returningColumn is unset, the single-statement inserter
	// works fine for MySQL as well.
	if !features.Get().UseMySQL || mi.returningColumn == "" {
		return mi.singleStatementInsert(ctx, tx)
	}
	return mi.mysqlInsert(ctx, tx)
}
