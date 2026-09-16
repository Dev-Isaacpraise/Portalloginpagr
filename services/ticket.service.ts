import crypto from 'crypto';

interface TicketData {
  user: any;
  expiresAt: number;
}

class TicketServiceClass {
  private pendingTickets = new Map<string, TicketData>();
  private authTickets = new Map<string, TicketData>();

  constructor() {
    // Periodically prune expired tokens
    setInterval(() => {
      const now = Date.now();
      for (const [k, v] of this.pendingTickets.entries()) {
        if (v.expiresAt < now) this.pendingTickets.delete(k);
      }
      for (const [k, v] of this.authTickets.entries()) {
        if (v.expiresAt < now) this.authTickets.delete(k);
      }
    }, 5 * 60 * 1000);
  }

  /**
   * Generates a temporary pending ticket for Step 1 -> Step 2 transition.
   * This guarantees that in iframe environments where third-party cookies
   * may be blocked by browser privacy policies (SameSite/ITP),
   * the multi-factor authentication step is NEVER lost.
   */
  createPendingTicket(user: any): string {
    const ticket = 'mfa_' + crypto.randomBytes(20).toString('hex');
    this.pendingTickets.set(ticket, {
      user,
      expiresAt: Date.now() + 15 * 60 * 1000 // 15 mins
    });
    return ticket;
  }

  getPendingTicket(ticket: string): any | null {
    if (!ticket) return null;
    const data = this.pendingTickets.get(ticket);
    if (!data) return null;
    if (data.expiresAt < Date.now()) {
      this.pendingTickets.delete(ticket);
      return null;
    }
    return data.user;
  }

  consumePendingTicket(ticket: string): any | null {
    const user = this.getPendingTicket(ticket);
    if (ticket) {
      this.pendingTickets.delete(ticket);
    }
    return user;
  }

  /**
   * Generates an authenticated session token for the user.
   */
  createAuthTicket(user: any): string {
    const ticket = 'auth_' + crypto.randomBytes(24).toString('hex');
    this.authTickets.set(ticket, {
      user,
      expiresAt: Date.now() + 4 * 60 * 60 * 1000 // 4 hours
    });
    return ticket;
  }

  getAuthTicket(ticket: string): any | null {
    if (!ticket) return null;
    const data = this.authTickets.get(ticket);
    if (!data) return null;
    if (data.expiresAt < Date.now()) {
      this.authTickets.delete(ticket);
      return null;
    }
    return data.user;
  }

  removeAuthTicket(ticket: string): void {
    if (ticket) this.authTickets.delete(ticket);
  }
}

export const TicketService = new TicketServiceClass();
