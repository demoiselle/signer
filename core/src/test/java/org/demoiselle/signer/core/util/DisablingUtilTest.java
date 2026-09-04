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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link DisablingUtil}.
 */
class DisablingUtilTest {

    private Map<String, String> env() {
        return new HashMap<>();
    }

    private Map<String, String> env(String key, String value) {
        Map<String, String> map = new HashMap<>();
        map.put(key, value);
        return map;
    }

    @Test
    void testDefaultBehavior_noVariableSet_chainEnabled() {
        // Without any environment variable, chains should be enabled (not disabled)
        assertFalse(DisablingUtil.isChainDisabled("test-chain", env()));
    }

    @Test
    void testExplicitDisable_true_chainDisabled() {
        assertTrue(DisablingUtil.isChainDisabled("test-chain", env("SIGNER_DISABLE_CHAIN_TEST_CHAIN", "true")));
    }

    @Test
    void testExplicitDisable_false_chainEnabled() {
        assertFalse(DisablingUtil.isChainDisabled("test-chain", env("SIGNER_DISABLE_CHAIN_TEST_CHAIN", "false")));
    }

    @Test
    void testExplicitDisable_emptyString_chainEnabled() {
        assertFalse(DisablingUtil.isChainDisabled("test-chain", env("SIGNER_DISABLE_CHAIN_TEST_CHAIN", "")));
    }

    @Test
    void testToDisableVariableName() {
        assertEquals("SIGNER_DISABLE_CHAIN_ICP_BRASIL_HOMOLOG",
                DisablingUtil.toDisableVariableName("icp-brasil-homolog"));
        assertEquals("SIGNER_DISABLE_CHAIN_ITI_HOMOLOG",
                DisablingUtil.toDisableVariableName("iti-homolog"));
        assertEquals("SIGNER_DISABLE_CHAIN_SERPRO_NEOSIGNER_HOMOLOG",
                DisablingUtil.toDisableVariableName("serpro-neosigner-homolog"));
    }

    @Test
    void testGetEnvironment_empty_default() {
        assertEquals("", DisablingUtil.getEnvironment(env()));
    }

    @Test
    void testGetEnvironment_withValue() {
        assertEquals("hom", DisablingUtil.getEnvironment(env("SIGNER_ENV", "hom")));
    }

    @Test
    void testHomologationChainDisabledByEnv_prod() {
        Map<String, String> e = env("SIGNER_ENV", "production");
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil-homolog", e));
    }

    @Test
    void testHomologationChainDisabledByEnv_hom() {
        Map<String, String> e = env("SIGNER_ENV", "hom");
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", e));
    }

    @Test
    void testProductionChainDisabledByEnv_hom() {
        Map<String, String> e = env("SIGNER_ENV", "hom");
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil", e));
    }

    @Test
    void testProductionChainEnabledByDefault() {
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil", env()));
    }

    @Test
    void testExplicitDisableTakesPrecedence() {
        Map<String, String> e = new HashMap<>();
        e.put("SIGNER_ENV", "hom");
        e.put("SIGNER_DISABLE_CHAIN_ICP_BRASIL", "true");
        assertTrue(DisablingUtil.isChainDisabled("icp-brasil", e));
    }

    @Test
    void testExplicitDisableHomologTakesPrecedence() {
        Map<String, String> e = new HashMap<>();
        e.put("SIGNER_ENV", "production");
        e.put("SIGNER_DISABLE_CHAIN_ICP_BRASIL_HOMOLOG", "false");
        assertFalse(DisablingUtil.isChainDisabled("icp-brasil-homolog", e));
    }
}
