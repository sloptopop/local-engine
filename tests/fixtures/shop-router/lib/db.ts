type Failure = { message: string };
type Result = { data: any; error: Failure | null };

interface Query extends PromiseLike<Result> {
  select(columns?: string): Query;
  insert(row: object): Query;
  update(row: object): Query;
  eq(column: string, value: unknown): Query;
  single(): Query;
  maybeSingle(): Query;
  throwOnError(): Query;
}

export declare const db: { from(table: string): Query };
