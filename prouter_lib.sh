#!/bin/sh


LOG="logger -t prouter[$$] -p"

VIRT_INTERFACE="10.101.101.101"
FWMARK="0xff00000"

PROBE_IPS="114.114.114.114 8.8.8.8"

CONNTRACK_FILE="/proc/net/nf_conntrack"

PROUTER_STATUS_DIR="/var/run/prouter"

readonly LOCKFILE="/var/run/prouter/lockfile"
readonly FD=$(ls -l /proc/$$/fd | sed -n '$p' | awk '{print $9}')
readonly LOCKFD=$((${FD} + 1))

prouter_lock() {
  eval "exec ${LOCKFD}>${LOCKFILE}"
  flock ${LOCKFD}
}

prouter_unlock() {
  flock -u ${LOCKFD}
  eval "exec ${LOCKFD}>&-"
}

prouter_init() {
  [ -d $PROUTER_STATUS_DIR ] || mkdir -p $PROUTER_STATUS_DIR
  [ -d $PROUTER_STATUS_DIR/iface_state ] || mkdir -p $PROUTER_STATUS_DIR/iface_state
}

id2fwmark() {
  printf "%x" $(($1 + 128))
}

prouter_set_general_iptables() {
  #将输入接口ppp+的udp包的目标ip修改为$VIRT_INTERFACE
  if ! iptables -w -t nat -S PREROUTING | grep ppp+ &>/dev/null; then
    iptables -w -t nat -A PREROUTING -i ppp+ -p udp -j DNAT --to-destination $VIRT_INTERFACE
  fi

  #将输出接口ppp+的包源ip修改为该dev设备的ip
  if ! iptables -w -t nat -S POSTROUTING | grep ppp+ &>/dev/null; then
    iptables -w -t nat -A POSTROUTING -o ppp+ -j MASQUERADE
  fi

  #创建prouter_setmark_inside 链
  if ! iptables -w -t mangle -S prouter_setmark_inside &>/dev/null; then
    iptables -w -t mangle -N prouter_setmark_inside
  fi

  #创建prouter_setmark 链, 在整个连接上打上标记
  #
  if ! iptables -w -t mangle -S prouter_setmark &>/dev/null; then
    iptables -w -t mangle -N prouter_setmark
    iptables -w -t mangle -A prouter_setmark -j CONNMARK --restore-mark --nfmask $FWMARK --ctmask $FWMARK
    iptables -w -t mangle -A prouter_setmark -j prouter_setmark_inside
    iptables -w -t mangle -A prouter_setmark -j CONNMARK --save-mark --nfmask $FWMARK --ctmask $FWMARK
  fi

  if ! iptables -w -t mangle -S INPUT | grep prouter_setmark &>/dev/null; then
    iptables -w -t mangle -A INPUT -i ppp+ -j prouter_setmark
  fi

  if ! iptables -w -t mangle -S prouter_lb &>/dev/null; then
    iptables -w -t mangle -N prouter_lb
  fi

  if ! iptables -w -t mangle -S OUTPUT | grep prouter_lb &>/dev/null; then
    iptables -w -t mangle -A OUTPUT -j CONNMARK --restore-mark --nfmask $FWMARK --ctmask $FWMARK
    iptables -w -t mangle -A OUTPUT -o virt1 -j prouter_lb
    iptables -w -t mangle -A OUTPUT -o virt1 -j MARK --set-xmark 0xA0000000/0xf0000000
    iptables -w -t mangle -A OUTPUT -j CONNMARK --save-mark --nfmask $FWMARK --ctmask $FWMARK
  fi

  if ! iptables -w -t nat -S PREROUTING | grep DOCKER &>/dev/null; then
    iptables -t nat -D PREROUTING 1
  fi
  
  #ipv6
  
  ipv6num=`cat /etc/ppp/pppoe_account |wc -l`
  
  if ! ip6tables -w -t mangle -S INPUT |grep ppp+ &>/dev/null; then
    ip6tables -t mangle -A INPUT -i ppp+ -m state --state NEW -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff
  fi

  if ! ip6tables -w -t mangle -S OUTPUT |grep 0xcafeface &>/dev/null; then
    ip6tables -t mangle -A OUTPUT -m state --state NEW -j HMARK --hmark-tuple src,sport,dst,dport --hmark-mod $ipv6num --hmark-rnd 0xcafeface --hmark-offset 0x10
  fi

  if ! ip6tables -w -t mangle -S OUTPUT  |grep "NEW -j CONNMARK" &>/dev/null; then
    ip6tables -t mangle -A OUTPUT -m state --state NEW -j CONNMARK --save-mark --nfmask 0xffffffff --ctmask 0xffffffff
  fi
  
  if ! ip6tables -w -t mangle -S OUTPUT  |grep "RELATED,ESTABLISHED -j" &>/dev/null; then
    ip6tables -t mangle -A OUTPUT -m state --state RELATED,ESTABLISHED -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff
  fi
}

prouter_set_general_rules() {
  $LOG notice "set general rules"
}

prouter_create_iface_iptables() {
  local iface index

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  iptables -w -t mangle -D prouter_setmark_inside -i ppp${index} -m mark --mark 0x0/$FWMARK -j MARK --set-xmark 0x$(id2fwmark $index)00000/$FWMARK &>/dev/null
  iptables -w -t mangle -A prouter_setmark_inside -i ppp${index} -m mark --mark 0x0/$FWMARK -j MARK --set-xmark 0x$(id2fwmark $index)00000/$FWMARK

}




prouter_create_iface_ip6tables() {
  local iface index

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  ipv6num=`cat /etc/ppp/pppoe_account |wc -l`
  
  
  tmp_num=$(printf 0x%x $[$index+16])
  egrep "$1\$" /etc/iproute2/rt_tables || echo "$tmp_num $1" >>/etc/iproute2/rt_tables
  
  
  ip -6 route flush table $1

  echo 0 >/proc/sys/net/ipv6/conf/${iface}/rp_filter
  echo 0 >/proc/sys/net/ipv6/conf/all/rp_filter
  echo 0 >/proc/sys/net/ipv6/conf/default/rp_filter
  
  ip6tables -t mangle -A INPUT -i $1 -m state --state NEW -j MARK --set-mark $(printf 0x%x $[$index+16])
  ip6tables -t nat -A POSTROUTING -o $1 -j MASQUERADE

  sleep 1
  
  new_ipaddr=`ifconfig $1|awk '$1~"inet" && $2~"^[0-9]"{print $2 }'`
  ipv6=`echo $new_ipaddr | awk '{print $2}'`
  ip -6 rule del from `ip -6 rule |grep $1| awk '{print $3}'| awk '$1~"^[0-9]"{print $1}' |grep -v "$ipv6"`
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1`
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1`
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1`
  
  ip -6 route flush table $1
  ip -6 rule add from $ipv6 table $1 pref 200
  ip -6 rule add fwmark $(printf 0x%x $[$index+16]) table $1 pref 100
  ip -6 route add ::/0 dev $1 table $1
}




prouter_create_iface_rules() {
  local iface index rc

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  # rc=`ip rule list fwmark 0x$(id2fwmark $index)00000/$FWMARK`
  # if [ -n "$rc" ]; then
  ip rule del fwmark 0x$(id2fwmark $index)00000/$FWMARK
  # fi

  ip rule add fwmark 0x$(id2fwmark $index)00000/$FWMARK table 1000${index} pref 20000

  echo 0 >/proc/sys/net/ipv4/conf/${iface}/rp_filter
  echo 0 >/proc/sys/net/ipv4/conf/all/rp_filter

}

prouter_create_iface_route() {
  local iface index table_id

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  table_id=1000${index}

  ip route flush table $table_id

  ip r add default dev ppp${index} table $table_id

}

prouter_delete_iface_iptables() {
  local iface index

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  iptables -w -t mangle -D prouter_setmark_inside -i ppp${index} -m mark --mark 0x0/$FWMARK -j MARK --set-xmark 0x$(id2fwmark $index)00000/$FWMARK &>/dev/null

}



prouter_delete_iface_ip6tables() {
  local iface index

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  new_ipaddr=`ifconfig $1|awk '$1~"inet" && $2~"^[0-9]"{print $2 }'`
  ipv6=`echo $new_ipaddr | awk '{print $2}'`
  ip -6 route flush table $1
  sleep 1
  ip -6 rule del from $ipv6 table $1
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1` table $1
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1` table $1
  ip -6 rule del from `ip -6 rule |grep -w "$1" | awk '$1~"200"{print $3 }' | head -1` table $1
  
  
  
}




prouter_delete_iface_rules() {
  local iface index rc

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  # rc=`ip rule list fwmark 0x$(id2fwmark $index)00000/$FWMARK`
  # if [ -n "$rc" ]; then
  ip rule del fwmark 0x$(id2fwmark $index)00000/$FWMARK
  # fi

}

prouter_delete_iface_route() {
  local iface index table_id

  iface=$1

  index=${iface:3:3}
  if ! [ "$index" -ge 0 ] 2>/dev/null; then
    $LOG warn "invalid interface: $iface"
    return 1
  fi

  table_id=1000${index}

  ip route flush table $table_id

}

prouter_set_policies() {
  local iface count probability iface_set first index pcount

  if ! iptables -w -t mangle -S prouter_lb &>/dev/null; then
    iptables -w -t mangle -N prouter_lb
  fi

  iptables -w -t mangle -F prouter_lb

  count=0
  iface_set=""

  for iface in $(ls $PROUTER_STATUS_DIR/iface_state/); do
    $LOG notice "interface: $iface"
    if [ "$(prouter_get_iface_hotplug_state $iface)" = "online" ]; then
      $LOG notice "online interface: $iface"
      iface_set="$iface_set $iface"
      count=$(($count + 1))
    fi
  done

  if [ $count = 0 ]; then
    $LOG warn "no interface available"
    return 1
  fi

  $LOG notice "total interface: $count, probability: $probability"

  pcount=1
  first=0
  for iface in $iface_set; do
    $LOG notice "online: $iface"

    index=${iface:3:3}
    if ! [ "$index" -ge 0 ] 2>/dev/null; then
      $LOG notice "invalid interface: $iface"
      return 1
    fi

    if [ $first = 0 ]; then
      first=1
      iptables -w -t mangle -A prouter_lb -m mark --mark 0x0/$FWMARK -j MARK --set-xmark 0x$(id2fwmark $index)00000/$FWMARK
      continue
    fi

    pcount=$(($pcount + 1))

    probability=$((1000 / $pcount))

    if [ "$probability" -lt 10 ]; then
      probability="0.00$probability"
    elif [ $probability -lt 100 ]; then
      probability="0.0$probability"
    elif [ $probability -lt 1000 ]; then
      probability="0.$probability"
    else
      probability="1"
    fi

    iptables -w -t mangle -I prouter_lb -m mark --mark 0x0/$FWMARK -m statistic --mode random --probability $probability -j MARK --set-xmark 0x$(id2fwmark $index)00000/$FWMARK
  done

}

prouter_probe() {
  local pid

  for pid in $(pgrep -f "prouter_prober $1"); do
    kill -TERM "$pid" >/dev/null 2>&1
    sleep 1
    kill -KILL "$pid" >/dev/null 2>&1
  done

  if [ -n "$PROBE_IPS" ]; then
    [ -x /usr/sbin/prouter_prober ] && /usr/sbin/prouter_prober "$1" "$2" "$3" "$4" $PROBE_IPS &
  fi

}

prouter_probe_signal() {
  local pid

  pid="$(pgrep -f "prouter_prober $1")"
  [ "${pid}" != "" ] && {
    kill -USR1 "${pid}"
  }
}

prouter_set_iface_hotplug_state() {
  local iface=$1
  local state=$2

  echo -n $state >$PROUTER_STATUS_DIR/iface_state/$iface
}

prouter_get_iface_hotplug_state() {
  local iface=$1

  cat $PROUTER_STATUS_DIR/iface_state/$iface 2>/dev/null || echo "offline"
}
