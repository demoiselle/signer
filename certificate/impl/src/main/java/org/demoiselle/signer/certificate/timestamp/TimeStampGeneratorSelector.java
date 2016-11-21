package org.demoiselle.signer.certificate.timestamp;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.ServiceLoader;
import java.util.Set;

import org.demoiselle.signer.certificate.Priority;
import org.demoiselle.signer.certificate.exception.CertificateCoreException;
// TODO Criar Exception
public final class TimeStampGeneratorSelector implements Serializable {

	private static final long serialVersionUID = 1L;

	private static ServiceLoader<TimeStampGenerator> loader;

	private TimeStampGeneratorSelector() {
	}

	public static TimeStampGenerator selectReference() {
		TimeStampGenerator selected = selectClass(getOptions());
		return selected;
	}

	private static Collection<TimeStampGenerator> getOptions() {
		Set<TimeStampGenerator> result = new HashSet<TimeStampGenerator>();

		loader = (ServiceLoader<TimeStampGenerator>) ServiceLoader.load(TimeStampGenerator.class);
		for (TimeStampGenerator clazz : loader) {
			result.add(clazz);
		}
		return result;
	}

	private static TimeStampGenerator selectClass(Collection<TimeStampGenerator> options) {
		TimeStampGenerator selected = null;

		for (TimeStampGenerator option : options) {
			if (selected == null || getPriority(option) < getPriority(selected)) {
				selected = option;
			}
		}

		if (selected != null) {
			performAmbiguityCheck(TimeStampGenerator.class, selected, options);
		}

		return selected;
	}

	private static int getPriority(TimeStampGenerator clazz) {
		int result = Priority.MAX_PRIORITY;
		Priority priority = clazz.getClass().getAnnotation(Priority.class);

		if (priority != null) {
			result = priority.value();
		}

		if (priority == null) {
			new CertificateCoreException("Favor sinalizar a Prioridade em: " + clazz.getClass().getName());
		}

		return result;
	}

	private static <T> void performAmbiguityCheck(Class<T> type, TimeStampGenerator selected, Collection<TimeStampGenerator> options) {
		int selectedPriority = getPriority(selected);

		List<TimeStampGenerator> ambiguous = new ArrayList<TimeStampGenerator>();

		for (TimeStampGenerator option : options) {
			if (selected != option && selectedPriority == getPriority(option)) {
				ambiguous.add(option);
			}
		}

		if (!ambiguous.isEmpty()) {
			ambiguous.add(selected);
			
			throw new CertificateCoreException("@Priority com ambiguidade em: " + selected.getClass().getCanonicalName());
		}
	}

}
