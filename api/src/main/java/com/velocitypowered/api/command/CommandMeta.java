/*
 * Copyright (C) 2018 Velocity Contributors
 *
 * The Velocity API is licensed under the terms of the MIT License. For more details,
 * reference the LICENSE file in the api top-level directory.
 */

package com.velocitypowered.api.command;

import com.mojang.brigadier.tree.CommandNode;
import java.util.Collection;

/**
 * Contains metadata for a {@link Command}.
 */
public interface CommandMeta {

  /**
   * Returns a non-empty collection containing the case-insensitive aliases
   * used to execute the command.
   *
   * @return the command aliases
   */
  Collection<String> aliases();

  /**
   * Returns an immutable collection containing command nodes that provide
   * additional argument metadata and tab-complete suggestions.
   * Note some {@link Command} implementations may not support hinting.
   *
   * @return the hinting command nodes
   */
  Collection<CommandNode<CommandSource>> hints();

  /**
   * Provides a fluent interface to create {@link CommandMeta}s.
   */
  interface Builder {

    /**
     * Specifies additional aliases that can be used to execute the command.
     *
     * @param aliases the command aliases
     * @return this builder, for chaining
     */
    Builder aliases(String... aliases);

    /**
     * Specifies a command node providing additional argument metadata and
     * tab-complete suggestions.
     *
     * @param node the command node
     * @return this builder, for chaining
     * @throws IllegalArgumentException if the node is executable, i.e. has a non-null
     *         {@link com.mojang.brigadier.Command}, or has a redirect.
     */
    Builder hint(CommandNode<CommandSource> node);

    /**
     * Returns a newly-created {@link CommandMeta} based on the specified parameters.
     *
     * @return the built {@link CommandMeta}
     */
    CommandMeta build();
  }
}
