spark_locals_without_parens = [server: 1]

[
  import_deps: [:ash, :plug],
  plugins: [Spark.Formatter, Styler],
  inputs: ["{mix,.formatter,.credo}.exs", "{config,lib,test}/**/*.{ex,exs}"],
  locals_without_parens: spark_locals_without_parens,
  export: [locals_without_parens: spark_locals_without_parens]
]
