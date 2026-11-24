defmodule ApiGatehouse.OAuth.Changes.GenerateTokens do
  @moduledoc """
  Assigns a freshly issued row the hash of its access token and, when the
  `refresh_expires_in` argument is set, of its refresh token; the moments each
  stops working; and returns the raw tokens as `:access_token` and
  `:refresh_token` action metadata (`nil` without a refresh token).

  Both values are generated here rather than accepted, so nothing a client sends
  can decide either. Only their hashes are persisted, which makes this the one
  and only point the raw tokens are readable.
  """

  use Ash.Resource.Change

  alias ApiGatehouse.OAuth.OpaqueToken
  alias Ash.Changeset

  @impl true
  @spec change(Changeset.t(), keyword(), Ash.Resource.Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    now = DateTime.utc_now()
    access_token = OpaqueToken.generate()
    expires_in = Changeset.get_argument(changeset, :expires_in)

    changeset
    |> Changeset.force_change_attribute(:token_hash, OpaqueToken.hash(access_token))
    |> Changeset.force_change_attribute(:expires_at, DateTime.shift(now, second: expires_in))
    |> with_refresh_token(
      Changeset.get_argument(changeset, :refresh_expires_in),
      now,
      access_token
    )
  end

  defp with_refresh_token(changeset, nil, _now, access_token) do
    Changeset.after_action(changeset, &issued(&1, &2, access_token, nil))
  end

  defp with_refresh_token(changeset, refresh_expires_in, now, access_token) do
    refresh_token = OpaqueToken.generate()

    changeset
    |> Changeset.force_change_attribute(:refresh_token_hash, OpaqueToken.hash(refresh_token))
    |> Changeset.force_change_attribute(
      :refresh_expires_at,
      DateTime.shift(now, second: refresh_expires_in)
    )
    |> Changeset.after_action(&issued(&1, &2, access_token, refresh_token))
  end

  defp issued(_changeset, row, access_token, refresh_token) do
    {:ok,
     row
     |> Ash.Resource.put_metadata(:access_token, access_token)
     |> Ash.Resource.put_metadata(:refresh_token, refresh_token)}
  end
end
