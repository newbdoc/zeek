// See the file "COPYING" in the main distribution directory for copyright.
//
// A notification framework to inform interested parties of modifications to
// selected global objects. To get notified about a change, derive a class
// from notifier::Receiver and register the interesting objects with the
// notification::Registry.

#pragma once

#include <unordered_map>
#include <cstdint>

namespace zeek::notifier::detail  {

class Modifiable;

/** Interface class for receivers of notifications. */
class Receiver {
public:
	Receiver();
	virtual ~Receiver();

	/**
	 * Callback executed when a register object has been modified.
	 *
	 * @param m object that was modified
	 */
	virtual void Modified(Modifiable* m) = 0;

	/**
	 * Callback executed when notification registry is terminating and
	 * no further modifications can possibly occur.
	 */
	virtual void Terminate() { }
};

/** Singleton class tracking all notification requests globally. */
class Registry {
public:
	~Registry();

	/**
	 * Registers a receiver to be informed when a modifiable object has
	 * changed.
	 *
	 * @param m object to track. Does not take ownership, but the object
	 * will automatically unregister itself on destruction.
	 *
	 * @param r receiver to notify on changes. Does not take ownershop,
	 * the receiver must remain valid as long as the registration stays
	 * in place.
	 */
	void Register(Modifiable* m, Receiver* r);

	/**
	 * Cancels a receiver's request to be informed about an object's
	 * modification. The arguments to the method must match what was
	 * originally registered.
	 *
	 * @param m object to no loger track.
	 *
	 * @param r receiver to no longer notify.
	 */
	void Unregister(Modifiable* m, Receiver* Receiver);

	/**
	 * Cancels any active receiver requests to be informed about a
	 * partilar object's modifications.
	 *
	 * @param m object to no loger track.
	 */
	void Unregister(Modifiable* m);

	/**
	 * Notifies all receivers that no further modifications will occur
	 * as the registry is shutting down.
	 */
	void Terminate();

private:
	friend class Modifiable;

	// Inform all registered receivers of a modification to an object.
	// Will be called from the object itself.
	void Modified(Modifiable* m);

	typedef std::unordered_multimap<Modifiable*, Receiver*> ModifiableMap;
	ModifiableMap registrations;
};

/**
 * Singleton object tracking all global notification requests.
 */
extern Registry registry;

/**
 * Base class for objects that can trigger notifications to receivers when
 * modified.
 */
class Modifiable {
public:
	/**
	 * Calling this method signals to all registered receivers that the
	 * object has been modified.
	 */
	void Modified()
		{
		if ( num_receivers )
			registry.Modified(this);
		}

protected:
	friend class Registry;

	virtual ~Modifiable();

	// Number of currently registered receivers.
	uint64_t num_receivers = 0;
};

} // namespace zeek::notifier::detail

namespace notifier {

	using Receiver [[deprecated("Remove in v4.1. Use zeek::notifier::detail::Receiver.")]] = zeek::notifier::detail::Receiver;
	using Registry [[deprecated("Remove in v4.1. Use zeek::notifier::detail::Registry.")]] = zeek::notifier::detail::Registry;
	using Modifiable [[deprecated("Remove in v4.1. Use zeek::notifier::detail::Modifiable.")]] = zeek::notifier::detail::Modifiable;

	extern zeek::notifier::detail::Registry& registry [[deprecated("Remove from v4.1. Use zeek::notifier::detail::registry.")]];

} // namespace notifier
