defmodule ApiGatehouse.Resource.Info do
  @moduledoc "Reads a client resource's `api_gatehouse` section."
  use Spark.InfoGenerator, extension: ApiGatehouse.Resource, sections: [:api_gatehouse]
end
