@load base/frameworks/notice

module Tenzir;

export {
	redef enum Notice::Type += {
		Tenzir::TEST
	};
}

event Conn::log_conn(rec: Conn::Info) {
  NOTICE([
      $note = TEST,
      $uid = rec$uid,
      $msg = "Test Threat Bus",
      $ts = rec$ts,
      $id = rec$id
  ]);
}
