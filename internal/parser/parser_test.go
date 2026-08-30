package parser

import "testing"

func TestParse(t *testing.T) {
	beacon := `[2024.01.01-00.00.00:000][ 0]LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: 1.2.3.4:43965, Name: IpConnection_0, Driver: BeaconNetDriver Def:BeaconNetDriver, IsServer: 1, PC: NULL, Owner: NULL, UniqueId: RedpointEOS:00022f92c00c4537b96cd84fbe3d4bae`
	game := `[2024.01.01-00.00.00:000][ 0]LogNet: NotifyAcceptedConnection: Name: Gorodok_RAAS_v2, RemoteAddr: 5.6.7.8:43993, Driver: GameNetDriver Def:GameNetDriver`
	// the attacker: no beacon auth, id never resolves
	invalid := `LogNet: UNetConnection::Close: [UNetConnection] RemoteAddr: 9.9.9.9:1234, Def:BeaconNetDriver, UniqueId: INVALID`

	if ev, ok := Parse(beacon); !ok || ev.Kind != KindBeaconAuthed ||
		ev.IP.String() != "1.2.3.4" || ev.EOSID != "00022f92c00c4537b96cd84fbe3d4bae" {
		t.Fatalf("beacon: %+v ok=%v", ev, ok)
	}
	if ev, ok := Parse(game); !ok || ev.Kind != KindGameAccepted || ev.IP.String() != "5.6.7.8" {
		t.Fatalf("game: %+v ok=%v", ev, ok)
	}
	if ev, ok := Parse(invalid); ok {
		t.Fatalf("INVALID must never allow-list: %+v", ev)
	}
	if _, ok := Parse("LogSquad: nothing to see here"); ok {
		t.Fatal("unrelated line matched")
	}
}
