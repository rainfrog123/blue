#!/usr/bin/env python3
"""
Stake.com Blackjack Automation Script
Extracted from HAR file analysis

DISCLAIMER: This script is for educational purposes only.
Use responsibly and in accordance with Stake.com's terms of service.

HOW TO GET FRESH TOKENS:
1. Open stake.com in Chrome and log in
2. Open Developer Tools (F12) -> Network tab
3. Go to the blackjack game
4. Find any request to stake.com/_api/
5. Look in Request Headers for:
   - x-access-token
   - x-lockdown-token
6. Copy those values below or set as environment variables:
   export STAKE_ACCESS_TOKEN="your_token"
   export STAKE_LOCKDOWN_TOKEN="your_token"
"""

import json
import os
import random
import string
import time
from typing import Any, Literal, Optional

import requests


class StakeBlackjack:
    """Client for Stake.com Blackjack API."""

    BASE_URL = "https://stake.com"
    
    HEADERS = {
        "accept": "*/*",
        "accept-language": "en-US,en-GB;q=0.9,en;q=0.8",
        "content-type": "application/json",
        "origin": "https://stake.com",
        "referer": "https://stake.com/casino/games/blackjack",
        "sec-ch-ua": '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    }

    def __init__(
        self,
        access_token: str,
        lockdown_token: Optional[str] = None,
        language: str = "en",
    ):
        """
        Initialize the Stake Blackjack client.

        Args:
            access_token: Your x-access-token from Stake.com
            lockdown_token: Optional x-lockdown-token for additional security
            language: Language preference (default: "en")
        """
        self.session = requests.Session()
        self.access_token = access_token
        self.lockdown_token = lockdown_token
        self.language = language
        self._setup_session()

    def _setup_session(self) -> None:
        """Configure session headers."""
        self.session.headers.update(self.HEADERS)
        self.session.headers["x-access-token"] = self.access_token
        self.session.headers["x-language"] = self.language
        if self.lockdown_token:
            self.session.headers["x-lockdown-token"] = self.lockdown_token

    def set_cookies(self, cookies: dict) -> None:
        """Set cookies for the session."""
        for name, value in cookies.items():
            self.session.cookies.set(name, value, domain="stake.com")

    @staticmethod
    def generate_identifier(length: int = 21) -> str:
        """Generate a random bet identifier."""
        chars = string.ascii_letters + string.digits + "_-"
        return "".join(random.choice(chars) for _ in range(length))

    def _post(self, endpoint: str, data: dict) -> dict:
        """Make a POST request to the API."""
        url = f"{self.BASE_URL}{endpoint}"
        response = self.session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def _graphql(self, query: str, variables: Optional[dict] = None, operation_name: Optional[str] = None) -> dict:
        """Execute a GraphQL query."""
        payload = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name
            headers = {
                "x-operation-name": operation_name,
                "x-operation-type": "query" if "query" in query.lower()[:20] else "mutation",
            }
            self.session.headers.update(headers)

        url = f"{self.BASE_URL}/_api/graphql"
        response = self.session.post(url, json=payload)
        response.raise_for_status()
        return response.json()

    def get_balances(self) -> dict:
        """Get user balances for all currencies."""
        query = """query UserBalances {
  user {
    id
    balances {
      available {
        amount
        currency
        __typename
      }
      vault {
        amount
        currency
        __typename
      }
      __typename
    }
    __typename
  }
}"""
        return self._graphql(query, operation_name="UserBalances")

    def get_active_bet(self) -> dict:
        """Check for any active blackjack bet."""
        return self._post("/_api/casino/active-bet/blackjack", {})

    def place_bet(
        self,
        amount: float,
        currency: str = "usdt",
        identifier: Optional[str] = None,
    ) -> dict:
        """
        Place a new blackjack bet.

        Args:
            amount: Bet amount in the specified currency
            currency: Currency code (e.g., "usdt", "btc", "eth")
            identifier: Optional bet identifier (auto-generated if not provided)

        Returns:
            API response with bet details and initial hand
        """
        if identifier is None:
            identifier = self.generate_identifier()

        data = {
            "identifier": identifier,
            "amount": amount,
            "currency": currency.lower(),
        }
        return self._post("/_api/casino/blackjack/bet", data)

    def action(
        self,
        action_type: Literal["hit", "stand", "double", "split"],
        identifier: str,
    ) -> dict:
        """
        Take an action on an active blackjack hand.

        Args:
            action_type: The action to take (hit, stand, double, split)
            identifier: The bet identifier

        Returns:
            API response with updated game state
        """
        data = {
            "action": action_type,
            "identifier": identifier,
        }
        return self._post("/_api/casino/blackjack/next", data)

    def hit(self, identifier: str) -> dict:
        """Request another card."""
        return self.action("hit", identifier)

    def stand(self, identifier: str) -> dict:
        """Stand with current hand."""
        return self.action("stand", identifier)

    def double_down(self, identifier: str) -> dict:
        """Double the bet and receive exactly one more card."""
        return self.action("double", identifier)

    def split(self, identifier: str) -> dict:
        """Split a pair into two hands."""
        return self.action("split", identifier)


def calculate_hand_value(cards: list) -> tuple[int, bool]:
    """
    Calculate the value of a blackjack hand.
    
    Returns:
        Tuple of (value, is_soft) where is_soft indicates if Ace is counted as 11
    """
    value = 0
    aces = 0
    
    for card in cards:
        rank = card.get("rank", card) if isinstance(card, dict) else card
        if rank in ["J", "Q", "K"]:
            value += 10
        elif rank == "A":
            aces += 1
            value += 11
        else:
            value += int(rank)
    
    soft = aces > 0
    while value > 21 and aces:
        value -= 10
        aces -= 1
        if aces == 0:
            soft = False
    
    return value, soft


def basic_strategy(
    player_cards: list,
    dealer_upcard: Any,
    can_double: bool = True,
    can_split: bool = True,
) -> Literal["hit", "stand", "double", "split"]:
    """
    Implement basic blackjack strategy.
    
    Args:
        player_cards: List of player's cards
        dealer_upcard: Dealer's visible card (rank or card dict)
        can_double: Whether doubling is allowed
        can_split: Whether splitting is allowed
    
    Returns:
        Recommended action
    """
    player_value, is_soft = calculate_hand_value(player_cards)
    
    if isinstance(dealer_upcard, dict):
        dealer_rank = dealer_upcard.get("rank", dealer_upcard)
    else:
        dealer_rank = dealer_upcard
    
    dealer_value = 10 if dealer_rank in ["J", "Q", "K", "10"] else (11 if dealer_rank == "A" else int(dealer_rank))
    
    if len(player_cards) == 2:
        rank1 = player_cards[0].get("rank") if isinstance(player_cards[0], dict) else player_cards[0]
        rank2 = player_cards[1].get("rank") if isinstance(player_cards[1], dict) else player_cards[1]
        
        if rank1 == rank2 and can_split:
            if rank1 in ["A", "8"]:
                return "split"
            if rank1 == "9" and dealer_value not in [7, 10, 11]:
                return "split"
            if rank1 in ["2", "3", "7"] and dealer_value <= 7:
                return "split"
            if rank1 == "6" and dealer_value <= 6:
                return "split"
            if rank1 == "4" and dealer_value in [5, 6]:
                return "split"
    
    if is_soft:
        if player_value >= 19:
            return "stand"
        if player_value == 18:
            if dealer_value >= 9:
                return "hit"
            if dealer_value <= 6 and can_double and len(player_cards) == 2:
                return "double"
            return "stand"
        if player_value == 17:
            if dealer_value in [3, 4, 5, 6] and can_double and len(player_cards) == 2:
                return "double"
            return "hit"
        if player_value in [15, 16]:
            if dealer_value in [4, 5, 6] and can_double and len(player_cards) == 2:
                return "double"
            return "hit"
        if player_value in [13, 14]:
            if dealer_value in [5, 6] and can_double and len(player_cards) == 2:
                return "double"
            return "hit"
        return "hit"
    
    if player_value >= 17:
        return "stand"
    if player_value >= 13:
        if dealer_value <= 6:
            return "stand"
        return "hit"
    if player_value == 12:
        if dealer_value in [4, 5, 6]:
            return "stand"
        return "hit"
    if player_value == 11:
        if can_double and len(player_cards) == 2:
            return "double"
        return "hit"
    if player_value == 10:
        if dealer_value <= 9 and can_double and len(player_cards) == 2:
            return "double"
        return "hit"
    if player_value == 9:
        if dealer_value in [3, 4, 5, 6] and can_double and len(player_cards) == 2:
            return "double"
        return "hit"
    
    return "hit"


def play_hand(client: StakeBlackjack, bet_amount: float, currency: str = "usdt") -> dict:
    """
    Play a complete blackjack hand using basic strategy.
    
    Args:
        client: StakeBlackjack client instance
        bet_amount: Amount to bet
        currency: Currency to use
    
    Returns:
        Final game result
    """
    identifier = client.generate_identifier()
    print(f"Placing bet: {bet_amount} {currency.upper()}")
    
    result = client.place_bet(bet_amount, currency, identifier)
    print(f"Bet placed. Identifier: {identifier}")
    
    while True:
        state = result.get("state", {})
        player_cards = state.get("playerCards", [])
        dealer_cards = state.get("dealerCards", [])
        
        if not player_cards or not dealer_cards:
            print("Game state not available")
            break
        
        player_value, is_soft = calculate_hand_value(player_cards)
        print(f"Player hand: {player_cards} (Value: {player_value}{'S' if is_soft else ''})")
        print(f"Dealer shows: {dealer_cards[0]}")
        
        if state.get("isComplete") or state.get("result"):
            print(f"Game complete! Result: {state.get('result')}")
            break
        
        can_double = state.get("canDouble", len(player_cards) == 2)
        can_split = state.get("canSplit", False)
        
        action = basic_strategy(player_cards, dealer_cards[0], can_double, can_split)
        print(f"Taking action: {action.upper()}")
        
        result = client.action(action, identifier)
        time.sleep(0.5)
    
    return result


def main():
    """Example usage of the Stake Blackjack client."""
    # Try environment variables first, then fall back to hardcoded (expired) tokens
    ACCESS_TOKEN = os.environ.get(
        "STAKE_ACCESS_TOKEN",
        "5deebe2004b9ac6a8ecc30294587b0ba111a9d1d24c63d8b85f77af0d14be45b5939b3376dbb401973bc661cedf84cbf"
    )
    LOCKDOWN_TOKEN = os.environ.get(
        "STAKE_LOCKDOWN_TOKEN",
        "s5MNWtjTM5TvCMkAzxov"
    )

    print("=" * 50)
    print("Stake Blackjack Automation")
    print("=" * 50)
    
    if "STAKE_ACCESS_TOKEN" not in os.environ:
        print("\nWARNING: Using tokens from HAR file (likely expired)")
        print("Set STAKE_ACCESS_TOKEN and STAKE_LOCKDOWN_TOKEN env vars")
        print("for fresh tokens from your browser session.\n")

    client = StakeBlackjack(
        access_token=ACCESS_TOKEN,
        lockdown_token=LOCKDOWN_TOKEN,
    )

    print("\n[1] Fetching balances...")
    try:
        balances = client.get_balances()
        print(json.dumps(balances, indent=2))
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e}")
        print("Token may be expired. Get a fresh token from your browser.")
        return

    print("\n[2] Checking for active bet...")
    try:
        active_bet = client.get_active_bet()
        print(json.dumps(active_bet, indent=2))
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e}")

    # Example: Play a hand with minimum bet
    print("\n[3] Playing a hand with 0.00000001 USDT (minimum bet)...")
    try:
        result = play_hand(client, bet_amount=0.00000001, currency="usdt")
        print("\nFinal result:")
        print(json.dumps(result, indent=2))
    except requests.exceptions.HTTPError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error during play: {e}")


if __name__ == "__main__":
    main()
