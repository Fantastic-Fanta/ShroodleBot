from __future__ import annotations

import discord


async def in_home_guild(
    user: discord.abc.User,
    *,
    client: discord.Client,
    guild_id: int,
    interaction_guild_id: int | None = None,
) -> bool:
    if interaction_guild_id == guild_id:
        return True
    if interaction_guild_id is not None:
        return False

    guild = client.get_guild(guild_id)
    if guild is None:
        try:
            guild = await client.fetch_guild(guild_id)
        except discord.HTTPException:
            return False

    member = guild.get_member(user.id)
    if member is not None:
        return True
    try:
        await guild.fetch_member(user.id)
    except discord.HTTPException:
        return False
    return True
