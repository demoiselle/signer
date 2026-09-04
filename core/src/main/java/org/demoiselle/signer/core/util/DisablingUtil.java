/*
 * Demoiselle Framework
 * Copyright (C) 2016 SERPRO
 * ----------------------------------------------------------------------------
 * This file is part of Demoiselle Framework.
 *
 * Demoiselle Framework is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License version 3
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License version 3
 * along with this program; if not,  see <http://www.gnu.org/licenses/>
 * or write to the Free Software Foundation, Inc., 51 Franklin Street,
 * Fifth Floor, Boston, MA  02110-1301, USA.
 * ----------------------------------------------------------------------------
 * Este arquivo é parte do Framework Demoiselle.
 *
 * O Framework Demoiselle é um software livre; você pode redistribuí-lo e/ou
 * modificá-lo dentro dos termos da GNU LGPL versão 3 como publicada pela Fundação
 * do Software Livre (FSF).
 *
 * Este programa é distribuído na esperança que possa ser útil, mas SEM NENHUMA
 * GARANTIA; sem uma garantia implícita de ADEQUAÇÃO a qualquer MERCADO ou
 * APLICAÇÃO EM PARTICULAR. Veja a Licença Pública Geral GNU/LGPL em português
 * para maiores detalhes.
 *
 * Você deve ter recebido uma cópia da GNU LGPL versão 3, sob o título
 * "LICENCA.txt", junto com esse programa. Se não, acesse <http://www.gnu.org/licenses/>
 * ou escreva para a Fundação do Software Livre (FSF) Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA 02111-1301, USA.
 */

package org.demoiselle.signer.core.util;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class to manage chain loading disabling via environment variables.
 * <p>
 * Each chain module can be individually disabled by setting the environment variable:
 * {@code SIGNER_DISABLE_CHAIN_<CHAIN_NAME>} to {@code true}, where CHAIN_NAME is the chain name
 * in upper case with dashes replaced by underscores (e.g., {@code SIGNER_DISABLE_CHAIN_ICP_BRASIL_HOMOLOG}).
 * <p>
 * By default, all chains are enabled (loaded) when their dependencies are present.
 * <p>
 * The global environment variable {@code SIGNER_ENV} is also respected when the per-chain
 * disable variable is not explicitly set:
 * <ul>
 *   <li>For homologation chains: if SIGNER_ENV is "production" or "prod", the chain is disabled</li>
 *   <li>For production chains: if SIGNER_ENV is "hom" or "homolog", the chain is disabled</li>
 * </ul>
 *
 * @since 4.6.3
 */
public final class DisablingUtil {

    private static final String DISABLE_ENV_PREFIX = "SIGNER_DISABLE_CHAIN_";
    private static final String ENV_VARIABLE = "SIGNER_ENV";

    private static final Logger LOGGER = LoggerFactory.getLogger(DisablingUtil.class);

    private DisablingUtil() {
        // Utility class - not instantiable
    }

    /**
     * Checks if a chain should be disabled.
     * <p>
     * Priority:
     * <ol>
     *   <li>If {@code SIGNER_DISABLE_CHAIN_<CHAIN_NAME>} is explicitly set, uses that value</li>
     *   <li>Otherwise, falls back to {@code SIGNER_ENV}-based behavior</li>
     * </ol>
     *
     * @param chainName the chain/module name (e.g., "icp-brasil-homolog", "iti-homolog")
     * @return true if the chain should be disabled, false if it should be loaded
     */
    public static boolean isChainDisabled(String chainName) {
        return isChainDisabled(chainName, System.getenv());
    }

    /**
     * Checks if a chain should be disabled based on the given environment variables.
     *
     * @param chainName the chain/module name
     * @param env       the environment variables map
     * @return true if the chain should be disabled, false if it should be loaded
     */
    static boolean isChainDisabled(String chainName, Map<String, String> env) {
        String variableName = toDisableVariableName(chainName);
        String variableValue = env.get(variableName);

        if (variableValue != null && !variableValue.trim().isEmpty()) {
            boolean disabled = Boolean.parseBoolean(variableValue.trim());
            if (disabled) {
                LOGGER.info("Chain '{}' disabled via environment variable: {}=true", chainName, variableName);
            }
            return disabled;
        }

        // No explicit disable variable - fall back to global env-based behavior
        return isChainDisabledByEnv(chainName, getEnvironment(env));
    }

    /**
     * Checks if a chain should be disabled based on the SIGNER_ENV value.
     * <p>
     * Homologation chains (containing "homolog" in name) are disabled when SIGNER_ENV=production|prod.
     * Production chains are disabled when SIGNER_ENV=hom|homolog.
     *
     * @param chainName the chain/module name
     * @param envValue  the value of SIGNER_ENV
     * @return true if the chain should be disabled by the global environment setting
     */
    private static boolean isChainDisabledByEnv(String chainName, String envValue) {

        if (envValue.isEmpty()) {
            // No env variable set - chain is enabled by default
            return false;
        }

        boolean isHomologChain = chainName.toLowerCase().contains("homolog");
        boolean isProductionEnv = "production".equalsIgnoreCase(envValue) || "prod".equalsIgnoreCase(envValue);

        if (isHomologChain && isProductionEnv) {
            LOGGER.info("Chain '{}' disabled by {}={} (homologation chains disabled in production)",
                    chainName, ENV_VARIABLE, envValue);
            return true;
        }

        if (!isHomologChain && ("hom".equalsIgnoreCase(envValue) || "homolog".equalsIgnoreCase(envValue))) {
            LOGGER.info("Chain '{}' disabled by {}={} (production chains disabled in homologation)",
                    chainName, ENV_VARIABLE, envValue);
            return true;
        }

        return false;
    }

    /**
     * Gets the environment type from the SIGNER_ENV environment variable.
     *
     * @return the environment value (empty string if not set)
     */
    public static String getEnvironment() {
        return getEnvironment(System.getenv());
    }

    /**
     * Gets the environment type from the given environment variables map.
     *
     * @param env the environment variables map
     * @return the environment value (empty string if not set)
     */
    static String getEnvironment(Map<String, String> env) {
        String value = env.get(ENV_VARIABLE);
        return value == null ? "" : value.trim();
    }

    /**
     * Converts a chain name to its disable environment variable name.
     * Example: "icp-brasil-homolog" becomes "SIGNER_DISABLE_CHAIN_ICP_BRASIL_HOMOLOG".
     *
     * @param chainName the chain/module name
     * @return the corresponding environment variable name
     */
    static String toDisableVariableName(String chainName) {
        return DISABLE_ENV_PREFIX + chainName.toUpperCase().replace('-', '_');
    }
}
