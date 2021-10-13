/**
 * Implements providers of ICP-Brasil Chain of Certificate Authorities.
 * Any provider must implement {@link org.demoiselle.signer.core.ca.provider.ProviderCA}.
 *
 * <p>Providers available:</p>
 * <ul>
 *     <li>Keystore provider ({@link org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilProviderCA})</li>
 *     <li>ITI provider ({@link org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilOnLineITIProviderCA})</li>
 *     <li>SERPRO provider ({@link org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilOnLineSerproProviderCA})</li>
 *     <li>File ACcompactado.zip ({@link org.demoiselle.signer.chain.icp.brasil.provider.impl.ICPBrasilUserHomeProviderCA})</li>
 * </ul>
 */
package org.demoiselle.signer.chain.icp.brasil.provider;
