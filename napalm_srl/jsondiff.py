# Copyright 2020 Nokia
# Licensed under the Apache License 2.0.
# SPDX-License-Identifier: Apache-2.0

import json
index_keys = ['name','id','index','sequence-id','buffer-name','address']

class jsondiff(object):
    """
    Class to find json diff
    """
    def __init__(self):
        pass
    def compare(self, newjsonfile, oldjsonfile):
        with open(newjsonfile, "r") as f:
            newjson = json.load(f)
        with open(oldjsonfile, "r") as f:
            oldjson = json.load(f)
        return self._cmp_dict(newjson, oldjson)

    def _cmp_dict(self, new, old, parent=""):
        result=[]
        keydiff = self._get_dict_key_diff(new, old)

        #step1 removed
        for k in keydiff["---"]:
            result.append({
                "---":"{}[{}]".format(parent, k),
                "value":old[k]
            })
        #step2 added
        for k in keydiff["+++"]:
            result.append({
                "+++":"{}[{}]".format(parent, k),
                "value": new[k]
            })

        #step3 modified
        for k in keydiff["common"]:
            if isinstance(old[k] ,dict) and isinstance(new[k] ,dict):
                res = self._cmp_dict(new[k], old[k], parent ="{}[{}]".format(parent, k))
                result.extend(res)
            elif isinstance(old[k], list) and isinstance(new[k] ,list):
                res = self._cmp_list(new[k],old[k],parent ="{}[{}]".format(parent,k))
                result.extend(res)
            else:
                if not old[k] == new[k]:
                    result.append({
                        "chg": "{}[{}]".format(parent, k),
                        "old_value": old[k],
                        "new_value":new[k]
                    })

        return result

    def _find_index_key(self, old_dicts):
        max_ct = 0
        key = None
        for i in index_keys:
            ct = 0
            for o in old_dicts:
                for k,v in o.items():
                    if k==i:
                        ct = ct +1
                        continue
            if ct >max_ct:
                max_ct = ct
                key = i
        if not max_ct==0:
            return key
        #find key either string or int and present in all/many dict and is unique

        print("{}\nType index key for above list:".format(old_dicts))
        return str(input())

    def _cmp_list(self, new, old_in, parent=""):
        result = []
        old = old_in[:]  # to capture ---
        old_dicts = [o for o in old if isinstance(o, dict)]
        old_has_list = any([o for o in old if isinstance(o, list)])
        ind_key = None
        if len(old_dicts) >1 :
            ind_key = self._find_index_key(old_dicts)
        for index,n in enumerate(new):

            # either n shd be in old
            # or n not in old , n is a dict and n not have indexkey
            # or n not in old , n is a dict and n have indexkey but no matching o
            # or n not in old , n is a dict and n have indexkey but has matching o to compare

            if n in old_in:
                if n in old: #if duplicat n is already removed.
                    old.remove(n)
                continue
            elif isinstance(n, dict):
                if len(old_dicts) == 0:
                    result.append({
                        "+++": "{}[{}]".format(parent, index),
                        "value": n
                    })
                    continue
                elif len(old_dicts) == 1:
                    res = self._cmp_dict(n,old_dicts[0],"{}[{}]".format(parent,index) )
                    result.extend(res)
                    old.remove(old_dicts[0])
                    continue
                elif not ind_key in n.keys():
                    result.append({
                        "+++":"{}[{}]".format(parent,index),
                        "value": n
                    })
                    continue
                else:
                    ind_key_value = n[ind_key]
                    o_to_compare = [o for o in old if ind_key in o and o[ind_key]==ind_key_value]
                    if len(o_to_compare)==0:
                        result.append({
                            "+++": "{}[{}]".format(parent, index),
                            "value": n
                        })
                        continue
                    else:
                        o_to_compare = o_to_compare[0]
                        old.remove(o_to_compare)
                        res = self._cmp_dict(n, o_to_compare, "{}[{}]".format(parent, index))
                        result.extend(res)
            elif isinstance(n, list):
                if not old_has_list:
                    result.append({
                        "+++": "{}[{}]".format(parent, index),
                        "value": n
                    })
                    continue
                else:
                    for o in old:
                        if isinstance(o, list):
                            old.remove(o)
                            res = self._cmp_list(n,o,"{}[{}]".format(parent, index))
                            result.extend(res)
                            continue
                    #if no more list available in o
                    result.append({
                        "+++": "{}[{}]".format(parent, index),
                        "value": n
                    })
                    continue
            else:
                result.append({
                    "+++": "{}[{}]".format(parent, index),
                    "value": n
                })
        if old:
            for index,o in enumerate(old_in):
                if o in old:
                    result.append({
                        "---": "{}[{}]".format(parent, index),
                        "value": o
                    })
        return result

    def _get_dict_key_diff(self, new, old):
        d1_keys = new.keys()
        d2_keys = old.keys()
        plus_ks = [k for k in d1_keys if k not in d2_keys]
        minus_ks = [k for k in d2_keys if k not in d1_keys]
        return {
            "+++":plus_ks,
            "---": minus_ks,
            "common": [k for k in d1_keys if k not in plus_ks],
        }
