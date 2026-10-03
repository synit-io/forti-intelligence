# Fortinet traffic investigation

## Language

**Connected ownership candidate**: A scoped FortiGate interface whose configured network contains an IP address. It is not proof of endpoint ownership, ingress, forwarding, reachability, or policy permission; overlapping networks can have multiple candidates.
_Avoid_: unique owner, route owner

**Interface scope**: The profile, ADOM, FortiGate, VDOM, and interface identifying one network attachment. Identical names in different scopes describe different attachments.

**Zone membership**: An interface's membership in a named policy zone within its FortiGate and VDOM. Equal zone names on different devices do not establish adjacency.

**Package target**: A policy package's assignment to a device and, where specified, a VDOM. Assignment does not prove installation or synchronization.
