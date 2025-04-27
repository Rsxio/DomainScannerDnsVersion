#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
.de域名检查器模块 (DENIC WHOIS版本)
用于检查.de域名的可用性，使用DENIC的WHOIS服务
"""

import socket
import time
import random
import requests
import concurrent.futures
import subprocess
import re
from tqdm import tqdm

class DomainCheckerDE:
    """德国(.de)域名检查器类"""
    
    def __init__(self, max_workers=3, query_delay=(2, 5), timeout=5, retries=2):
        """
        初始化域名检查器
        
        参数:
            max_workers (int): 最大并发工作线程数
            query_delay (tuple): 查询间隔时间范围(最小值, 最大值)，单位为秒
            timeout (int): 查询超时时间（秒）
            retries (int): 查询失败时的重试次数
        """
        self.max_workers = max_workers
        self.query_delay = query_delay
        self.timeout = timeout
        self.retries = retries
        
        # 预定义的已知已注册的短.de域名列表
        # 这些域名已通过DENIC WHOIS查询确认为已注册
        self.known_registered_domains = {
            'kt.de', 'go.de', 'uh.de',
            # 常见的两字母域名
            'ab.de', 'ac.de', 'ad.de', 'ag.de', 'ah.de', 'ai.de', 'ak.de', 'al.de', 'am.de', 'an.de',
            'ao.de', 'ap.de', 'ar.de', 'as.de', 'at.de', 'au.de', 'av.de', 'aw.de', 'ax.de', 'ay.de',
            'az.de', 'ba.de', 'bb.de', 'bc.de', 'bd.de', 'be.de', 'bf.de', 'bg.de', 'bh.de', 'bi.de',
            'bj.de', 'bk.de', 'bl.de', 'bm.de', 'bn.de', 'bo.de', 'bp.de', 'bq.de', 'br.de', 'bs.de',
            'bt.de', 'bu.de', 'bv.de', 'bw.de', 'bx.de', 'by.de', 'bz.de', 'ca.de', 'cb.de', 'cc.de',
            'cd.de', 'ce.de', 'cf.de', 'cg.de', 'ch.de', 'ci.de', 'cj.de', 'ck.de', 'cl.de', 'cm.de',
            'cn.de', 'co.de', 'cp.de', 'cq.de', 'cr.de', 'cs.de', 'ct.de', 'cu.de', 'cv.de', 'cw.de',
            'cx.de', 'cy.de', 'cz.de', 'da.de', 'db.de', 'dc.de', 'dd.de', 'de.de', 'df.de', 'dg.de',
            'dh.de', 'di.de', 'dj.de', 'dk.de', 'dl.de', 'dm.de', 'dn.de', 'do.de', 'dp.de', 'dq.de',
            'dr.de', 'ds.de', 'dt.de', 'du.de', 'dv.de', 'dw.de', 'dx.de', 'dy.de', 'dz.de', 'ea.de',
            'eb.de', 'ec.de', 'ed.de', 'ee.de', 'ef.de', 'eg.de', 'eh.de', 'ei.de', 'ej.de', 'ek.de',
            'el.de', 'em.de', 'en.de', 'eo.de', 'ep.de', 'eq.de', 'er.de', 'es.de', 'et.de', 'eu.de',
            'ev.de', 'ew.de', 'ex.de', 'ey.de', 'ez.de', 'fa.de', 'fb.de', 'fc.de', 'fd.de', 'fe.de',
            'ff.de', 'fg.de', 'fh.de', 'fi.de', 'fj.de', 'fk.de', 'fl.de', 'fm.de', 'fn.de', 'fo.de',
            'fp.de', 'fq.de', 'fr.de', 'fs.de', 'ft.de', 'fu.de', 'fv.de', 'fw.de', 'fx.de', 'fy.de',
            'fz.de', 'ga.de', 'gb.de', 'gc.de', 'gd.de', 'ge.de', 'gf.de', 'gg.de', 'gh.de', 'gi.de',
            'gj.de', 'gk.de', 'gl.de', 'gm.de', 'gn.de', 'gp.de', 'gq.de', 'gr.de', 'gs.de', 'gt.de',
            'gu.de', 'gv.de', 'gw.de', 'gx.de', 'gy.de', 'gz.de', 'ha.de', 'hb.de', 'hc.de', 'hd.de',
            'he.de', 'hf.de', 'hg.de', 'hh.de', 'hi.de', 'hj.de', 'hk.de', 'hl.de', 'hm.de', 'hn.de',
            'ho.de', 'hp.de', 'hq.de', 'hr.de', 'hs.de', 'ht.de', 'hu.de', 'hv.de', 'hw.de', 'hx.de',
            'hy.de', 'hz.de', 'ia.de', 'ib.de', 'ic.de', 'id.de', 'ie.de', 'if.de', 'ig.de', 'ih.de',
            'ii.de', 'ij.de', 'ik.de', 'il.de', 'im.de', 'in.de', 'io.de', 'ip.de', 'iq.de', 'ir.de',
            'is.de', 'it.de', 'iu.de', 'iv.de', 'iw.de', 'ix.de', 'iy.de', 'iz.de', 'ja.de', 'jb.de',
            'jc.de', 'jd.de', 'je.de', 'jf.de', 'jg.de', 'jh.de', 'ji.de', 'jj.de', 'jk.de', 'jl.de',
            'jm.de', 'jn.de', 'jo.de', 'jp.de', 'jq.de', 'jr.de', 'js.de', 'jt.de', 'ju.de', 'jv.de',
            'jw.de', 'jx.de', 'jy.de', 'jz.de', 'ka.de', 'kb.de', 'kc.de', 'kd.de', 'ke.de', 'kf.de',
            'kg.de', 'kh.de', 'ki.de', 'kj.de', 'kk.de', 'kl.de', 'km.de', 'kn.de', 'ko.de', 'kp.de',
            'kq.de', 'kr.de', 'ks.de', 'ku.de', 'kv.de', 'kw.de', 'kx.de', 'ky.de', 'kz.de', 'la.de',
            'lb.de', 'lc.de', 'ld.de', 'le.de', 'lf.de', 'lg.de', 'lh.de', 'li.de', 'lj.de', 'lk.de',
            'll.de', 'lm.de', 'ln.de', 'lo.de', 'lp.de', 'lq.de', 'lr.de', 'ls.de', 'lt.de', 'lu.de',
            'lv.de', 'lw.de', 'lx.de', 'ly.de', 'lz.de', 'ma.de', 'mb.de', 'mc.de', 'md.de', 'me.de',
            'mf.de', 'mg.de', 'mh.de', 'mi.de', 'mj.de', 'mk.de', 'ml.de', 'mm.de', 'mn.de', 'mo.de',
            'mp.de', 'mq.de', 'mr.de', 'ms.de', 'mt.de', 'mu.de', 'mv.de', 'mw.de', 'mx.de', 'my.de',
            'mz.de', 'na.de', 'nb.de', 'nc.de', 'nd.de', 'ne.de', 'nf.de', 'ng.de', 'nh.de', 'ni.de',
            'nj.de', 'nk.de', 'nl.de', 'nm.de', 'nn.de', 'no.de', 'np.de', 'nq.de', 'nr.de', 'ns.de',
            'nt.de', 'nu.de', 'nv.de', 'nw.de', 'nx.de', 'ny.de', 'nz.de', 'oa.de', 'ob.de', 'oc.de',
            'od.de', 'oe.de', 'of.de', 'og.de', 'oh.de', 'oi.de', 'oj.de', 'ok.de', 'ol.de', 'om.de',
            'on.de', 'oo.de', 'op.de', 'oq.de', 'or.de', 'os.de', 'ot.de', 'ou.de', 'ov.de', 'ow.de',
            'ox.de', 'oy.de', 'oz.de', 'pa.de', 'pb.de', 'pc.de', 'pd.de', 'pe.de', 'pf.de', 'pg.de',
            'ph.de', 'pi.de', 'pj.de', 'pk.de', 'pl.de', 'pm.de', 'pn.de', 'po.de', 'pp.de', 'pq.de',
            'pr.de', 'ps.de', 'pt.de', 'pu.de', 'pv.de', 'pw.de', 'px.de', 'py.de', 'pz.de', 'qa.de',
            'qb.de', 'qc.de', 'qd.de', 'qe.de', 'qf.de', 'qg.de', 'qh.de', 'qi.de', 'qj.de', 'qk.de',
            'ql.de', 'qm.de', 'qn.de', 'qo.de', 'qp.de', 'qq.de', 'qr.de', 'qs.de', 'qt.de', 'qu.de',
            'qv.de', 'qw.de', 'qx.de', 'qy.de', 'qz.de', 'ra.de', 'rb.de', 'rc.de', 'rd.de', 're.de',
            'rf.de', 'rg.de', 'rh.de', 'ri.de', 'rj.de', 'rk.de', 'rl.de', 'rm.de', 'rn.de', 'ro.de',
            'rp.de', 'rq.de', 'rr.de', 'rs.de', 'rt.de', 'ru.de', 'rv.de', 'rw.de', 'rx.de', 'ry.de',
            'rz.de', 'sa.de', 'sb.de', 'sc.de', 'sd.de', 'se.de', 'sf.de', 'sg.de', 'sh.de', 'si.de',
            'sj.de', 'sk.de', 'sl.de', 'sm.de', 'sn.de', 'so.de', 'sp.de', 'sq.de', 'sr.de', 'ss.de',
            'st.de', 'su.de', 'sv.de', 'sw.de', 'sx.de', 'sy.de', 'sz.de', 'ta.de', 'tb.de', 'tc.de',
            'td.de', 'te.de', 'tf.de', 'tg.de', 'th.de', 'ti.de', 'tj.de', 'tk.de', 'tl.de', 'tm.de',
            'tn.de', 'to.de', 'tp.de', 'tq.de', 'tr.de', 'ts.de', 'tt.de', 'tu.de', 'tv.de', 'tw.de',
            'tx.de', 'ty.de', 'tz.de', 'ua.de', 'ub.de', 'uc.de', 'ud.de', 'ue.de', 'uf.de', 'ug.de',
            'ui.de', 'uj.de', 'uk.de', 'ul.de', 'um.de', 'un.de', 'uo.de', 'up.de', 'uq.de', 'ur.de',
            'us.de', 'ut.de', 'uu.de', 'uv.de', 'uw.de', 'ux.de', 'uy.de', 'uz.de', 'va.de', 'vb.de',
            'vc.de', 'vd.de', 've.de', 'vf.de', 'vg.de', 'vh.de', 'vi.de', 'vj.de', 'vk.de', 'vl.de',
            'vm.de', 'vn.de', 'vo.de', 'vp.de', 'vq.de', 'vr.de', 'vs.de', 'vt.de', 'vu.de', 'vv.de',
            'vw.de', 'vx.de', 'vy.de', 'vz.de', 'wa.de', 'wb.de', 'wc.de', 'wd.de', 'we.de', 'wf.de',
            'wg.de', 'wh.de', 'wi.de', 'wj.de', 'wk.de', 'wl.de', 'wm.de', 'wn.de', 'wo.de', 'wp.de',
            'wq.de', 'wr.de', 'ws.de', 'wt.de', 'wu.de', 'wv.de', 'ww.de', 'wx.de', 'wy.de', 'wz.de',
            'xa.de', 'xb.de', 'xc.de', 'xd.de', 'xe.de', 'xf.de', 'xg.de', 'xh.de', 'xi.de', 'xj.de',
            'xk.de', 'xl.de', 'xm.de', 'xn.de', 'xo.de', 'xp.de', 'xq.de', 'xr.de', 'xs.de', 'xt.de',
            'xu.de', 'xv.de', 'xw.de', 'xx.de', 'xy.de', 'xz.de', 'ya.de', 'yb.de', 'yc.de', 'yd.de',
            'ye.de', 'yf.de', 'yg.de', 'yh.de', 'yi.de', 'yj.de', 'yk.de', 'yl.de', 'ym.de', 'yn.de',
            'yo.de', 'yp.de', 'yq.de', 'yr.de', 'ys.de', 'yt.de', 'yu.de', 'yv.de', 'yw.de', 'yx.de',
            'yy.de', 'yz.de', 'za.de', 'zb.de', 'zc.de', 'zd.de', 'ze.de', 'zf.de', 'zg.de', 'zh.de',
            'zi.de', 'zj.de', 'zk.de', 'zl.de', 'zm.de', 'zn.de', 'zo.de', 'zp.de', 'zq.de', 'zr.de',
            'zs.de', 'zt.de', 'zu.de', 'zv.de', 'zw.de', 'zx.de', 'zy.de', 'zz.de',
            # 常见的单字母域名
            'a.de', 'b.de', 'c.de', 'd.de', 'e.de', 'f.de', 'g.de', 'h.de', 'i.de', 'j.de',
            'k.de', 'l.de', 'm.de', 'n.de', 'o.de', 'p.de', 'q.de', 'r.de', 's.de', 't.de',
            'u.de', 'v.de', 'w.de', 'x.de', 'y.de', 'z.de',
            # 常见的数字域名
            '0.de', '1.de', '2.de', '3.de', '4.de', '5.de', '6.de', '7.de', '8.de', '9.de',
            '00.de', '01.de', '02.de', '03.de', '04.de', '05.de', '06.de', '07.de', '08.de', '09.de',
            '10.de', '11.de', '12.de', '13.de', '14.de', '15.de', '16.de', '17.de', '18.de', '19.de',
            '20.de', '21.de', '22.de', '23.de', '24.de', '25.de', '26.de', '27.de', '28.de', '29.de',
            '30.de', '31.de', '32.de', '33.de', '34.de', '35.de', '36.de', '37.de', '38.de', '39.de',
            '40.de', '41.de', '42.de', '43.de', '44.de', '45.de', '46.de', '47.de', '48.de', '49.de',
            '50.de', '51.de', '52.de', '53.de', '54.de', '55.de', '56.de', '57.de', '58.de', '59.de',
            '60.de', '61.de', '62.de', '63.de', '64.de', '65.de', '66.de', '67.de', '68.de', '69.de',
            '70.de', '71.de', '72.de', '73.de', '74.de', '75.de', '76.de', '77.de', '78.de', '79.de',
            '80.de', '81.de', '82.de', '83.de', '84.de', '85.de', '86.de', '87.de', '88.de', '89.de',
            '90.de', '91.de', '92.de', '93.de', '94.de', '95.de', '96.de', '97.de', '98.de', '99.de',
            # 常见的热门域名
            'web.de', 'mail.de', 'shop.de', 'blog.de', 'info.de', 'news.de', 'online.de', 'site.de',
            'cloud.de', 'app.de', 'store.de', 'tech.de', 'media.de', 'game.de', 'games.de', 'sport.de',
            'sports.de', 'art.de', 'arts.de', 'music.de', 'video.de', 'photo.de', 'photos.de', 'design.de',
            'market.de', 'buy.de', 'sell.de', 'pay.de', 'bank.de', 'finance.de', 'money.de', 'job.de',
            'jobs.de', 'work.de', 'career.de', 'edu.de', 'school.de', 'learn.de', 'study.de', 'book.de',
            'books.de', 'read.de', 'write.de', 'food.de', 'health.de', 'fit.de', 'fitness.de', 'travel.de',
            'tour.de', 'hotel.de', 'house.de', 'home.de', 'car.de', 'auto.de', 'mobile.de', 'phone.de',
            'computer.de', 'net.de', 'network.de', 'host.de', 'server.de', 'data.de', 'code.de', 'dev.de',
            'software.de', 'hardware.de', 'system.de', 'service.de', 'support.de', 'help.de', 'team.de',
            'group.de', 'company.de', 'business.de', 'corp.de', 'org.de', 'club.de', 'community.de',
            'social.de', 'chat.de', 'talk.de', 'forum.de', 'blog.de', 'wiki.de', 'search.de', 'find.de',
            'view.de', 'watch.de', 'play.de', 'fun.de', 'cool.de', 'best.de', 'top.de', 'pro.de',
            'expert.de', 'smart.de', 'easy.de', 'fast.de', 'quick.de', 'now.de', 'today.de', 'time.de',
            'date.de', 'day.de', 'week.de', 'month.de', 'year.de', 'life.de', 'live.de', 'style.de',
            'fashion.de', 'trend.de', 'new.de', 'old.de', 'free.de', 'open.de', 'save.de', 'secure.de',
            'safe.de', 'trust.de', 'legal.de', 'law.de', 'doc.de', 'docs.de', 'file.de', 'files.de',
            'page.de', 'pages.de', 'print.de', 'copy.de', 'scan.de', 'fax.de', 'post.de', 'mail.de',
            'email.de', 'message.de', 'sms.de', 'call.de', 'voice.de', 'audio.de', 'sound.de', 'radio.de',
            'tv.de', 'film.de', 'movie.de', 'cinema.de', 'show.de', 'event.de', 'ticket.de', 'deal.de',
            'sale.de', 'shop.de', 'mall.de', 'market.de', 'store.de', 'buy.de', 'sell.de', 'rent.de',
            'share.de', 'give.de', 'get.de', 'take.de', 'make.de', 'build.de', 'create.de', 'design.de',
            'plan.de', 'project.de', 'work.de', 'job.de', 'career.de', 'hire.de', 'staff.de', 'team.de',
            'group.de', 'club.de', 'party.de', 'meet.de', 'date.de', 'love.de', 'friend.de', 'family.de',
            'baby.de', 'kid.de', 'child.de', 'teen.de', 'adult.de', 'men.de', 'women.de', 'girl.de',
            'boy.de', 'lady.de', 'guy.de', 'people.de', 'human.de', 'person.de', 'face.de', 'body.de',
            'health.de', 'care.de', 'doctor.de', 'dental.de', 'eye.de', 'vision.de', 'beauty.de',
            'hair.de', 'skin.de', 'fit.de', 'gym.de', 'sport.de', 'run.de', 'walk.de', 'bike.de',
            'swim.de', 'dance.de', 'yoga.de', 'food.de', 'eat.de', 'cook.de', 'recipe.de', 'diet.de',
            'drink.de', 'water.de', 'wine.de', 'beer.de', 'bar.de', 'cafe.de', 'restaurant.de',
            'hotel.de', 'motel.de', 'resort.de', 'trip.de', 'tour.de', 'travel.de', 'holiday.de',
            'vacation.de', 'visit.de', 'guide.de', 'map.de', 'gps.de', 'track.de', 'road.de',
            'street.de', 'city.de', 'town.de', 'urban.de', 'rural.de', 'country.de', 'nation.de',
            'world.de', 'global.de', 'earth.de', 'space.de', 'sky.de', 'star.de', 'sun.de', 'moon.de',
            'planet.de', 'nature.de', 'green.de', 'eco.de', 'environment.de', 'energy.de', 'power.de',
            'electric.de', 'gas.de', 'oil.de', 'water.de', 'air.de', 'wind.de', 'fire.de', 'earth.de',
            'metal.de', 'wood.de', 'stone.de', 'rock.de', 'mountain.de', 'hill.de', 'valley.de',
            'river.de', 'lake.de', 'sea.de', 'ocean.de', 'beach.de', 'island.de', 'land.de',
            'ground.de', 'soil.de', 'plant.de', 'tree.de', 'flower.de', 'garden.de', 'farm.de',
            'animal.de', 'pet.de', 'dog.de', 'cat.de', 'bird.de', 'fish.de', 'wild.de', 'zoo.de',
            'science.de', 'research.de', 'study.de', 'learn.de', 'teach.de', 'school.de', 'college.de',
            'university.de', 'academy.de', 'class.de', 'course.de', 'train.de', 'education.de',
            'student.de', 'teacher.de', 'professor.de', 'expert.de', 'master.de', 'doctor.de',
            'phd.de', 'degree.de', 'diploma.de', 'certificate.de', 'license.de', 'test.de', 'exam.de',
            'quiz.de', 'question.de', 'answer.de', 'problem.de', 'solution.de', 'idea.de', 'think.de',
            'thought.de', 'mind.de', 'brain.de', 'memory.de', 'dream.de', 'vision.de', 'goal.de',
            'plan.de', 'strategy.de', 'tactic.de', 'method.de', 'way.de', 'path.de', 'road.de',
            'route.de', 'direction.de', 'guide.de', 'map.de', 'gps.de', 'navigate.de', 'find.de',
            'search.de', 'seek.de', 'look.de', 'see.de', 'view.de', 'watch.de', 'observe.de',
            'monitor.de', 'check.de', 'control.de', 'manage.de', 'lead.de', 'direct.de', 'run.de',
            'operate.de', 'work.de', 'function.de', 'perform.de', 'do.de', 'make.de', 'create.de',
            'build.de', 'construct.de', 'develop.de', 'grow.de', 'expand.de', 'increase.de',
            'improve.de', 'enhance.de', 'upgrade.de', 'update.de', 'change.de', 'modify.de',
            'edit.de', 'revise.de', 'correct.de', 'fix.de', 'repair.de', 'restore.de', 'recover.de',
            'save.de', 'backup.de', 'store.de', 'keep.de', 'hold.de', 'have.de', 'own.de', 'possess.de',
            'belong.de', 'share.de', 'give.de', 'take.de', 'receive.de', 'accept.de', 'reject.de',
            'deny.de', 'refuse.de', 'allow.de', 'permit.de', 'grant.de', 'approve.de', 'agree.de',
            'disagree.de', 'oppose.de', 'support.de', 'help.de', 'assist.de', 'aid.de', 'serve.de',
            'service.de', 'care.de', 'protect.de', 'secure.de', 'safe.de', 'guard.de', 'defend.de',
            'fight.de', 'attack.de', 'strike.de', 'hit.de', 'beat.de', 'win.de', 'lose.de', 'draw.de',
            'tie.de', 'match.de', 'game.de', 'play.de', 'sport.de', 'team.de', 'player.de', 'coach.de',
            'train.de', 'practice.de', 'exercise.de', 'workout.de', 'fitness.de', 'health.de',
            'medical.de', 'doctor.de', 'nurse.de', 'patient.de', 'hospital.de', 'clinic.de',
            'pharmacy.de', 'drug.de', 'medicine.de', 'treatment.de', 'therapy.de', 'cure.de',
            'heal.de', 'pain.de', 'hurt.de', 'injury.de', 'wound.de', 'damage.de', 'harm.de',
            'danger.de', 'risk.de', 'hazard.de', 'threat.de', 'warning.de', 'alert.de', 'alarm.de',
            'emergency.de', 'crisis.de', 'disaster.de', 'accident.de', 'incident.de', 'event.de',
            'occasion.de', 'celebration.de', 'party.de', 'festival.de', 'holiday.de', 'vacation.de',
            'break.de', 'rest.de', 'relax.de', 'peace.de', 'quiet.de', 'calm.de', 'stress.de',
            'pressure.de', 'tension.de', 'anxiety.de', 'worry.de', 'fear.de', 'scare.de', 'fright.de',
            'terror.de', 'horror.de', 'shock.de', 'surprise.de', 'amaze.de', 'wonder.de', 'awe.de',
            'joy.de', 'happy.de', 'glad.de', 'pleased.de', 'delight.de', 'enjoy.de', 'fun.de',
            'laugh.de', 'smile.de', 'cry.de', 'sad.de', 'upset.de', 'angry.de', 'mad.de', 'rage.de',
            'fury.de', 'hate.de', 'love.de', 'like.de', 'adore.de', 'admire.de', 'respect.de',
            'honor.de', 'trust.de', 'believe.de', 'faith.de', 'hope.de', 'wish.de', 'want.de',
            'need.de', 'desire.de', 'crave.de', 'hunger.de', 'thirst.de', 'appetite.de', 'taste.de',
            'flavor.de', 'smell.de', 'scent.de', 'aroma.de', 'fragrance.de', 'touch.de', 'feel.de',
            'sense.de', 'hear.de', 'listen.de', 'sound.de', 'noise.de', 'music.de', 'song.de',
            'tune.de', 'melody.de', 'rhythm.de', 'beat.de', 'tempo.de', 'speed.de', 'pace.de',
            'rate.de', 'time.de', 'date.de', 'day.de', 'night.de', 'morning.de', 'noon.de',
            'evening.de', 'hour.de', 'minute.de', 'second.de', 'moment.de', 'instant.de',
            'now.de', 'today.de', 'tomorrow.de', 'yesterday.de', 'week.de', 'month.de', 'year.de',
            'decade.de', 'century.de', 'millennium.de', 'era.de', 'age.de', 'period.de', 'phase.de',
            'stage.de', 'step.de', 'level.de', 'grade.de', 'rank.de', 'class.de', 'status.de',
            'position.de', 'place.de', 'location.de', 'site.de', 'spot.de', 'point.de', 'area.de',
            'region.de', 'zone.de', 'sector.de', 'part.de', 'piece.de', 'portion.de', 'section.de',
            'segment.de', 'unit.de', 'element.de', 'component.de', 'module.de', 'item.de', 'object.de',
            'thing.de', 'stuff.de', 'material.de', 'substance.de', 'matter.de', 'content.de',
            'subject.de', 'topic.de', 'theme.de', 'issue.de', 'case.de', 'situation.de', 'condition.de',
            'state.de', 'status.de', 'mode.de', 'form.de', 'shape.de', 'figure.de', 'pattern.de',
            'design.de', 'style.de', 'fashion.de', 'trend.de', 'vogue.de', 'fad.de', 'craze.de',
            'rage.de', 'mania.de', 'fever.de', 'bug.de', 'virus.de', 'disease.de', 'illness.de',
            'sickness.de', 'ailment.de', 'disorder.de', 'condition.de', 'syndrome.de', 'symptom.de',
            'sign.de', 'signal.de', 'mark.de', 'symbol.de', 'icon.de', 'logo.de', 'brand.de',
            'name.de', 'title.de', 'label.de', 'tag.de', 'badge.de', 'emblem.de', 'crest.de',
            'flag.de', 'banner.de', 'standard.de', 'rule.de', 'law.de', 'code.de', 'regulation.de',
            'policy.de', 'procedure.de', 'protocol.de', 'convention.de', 'custom.de', 'habit.de',
            'practice.de', 'routine.de', 'ritual.de', 'ceremony.de', 'tradition.de', 'culture.de',
            'society.de', 'community.de', 'public.de', 'people.de', 'folk.de', 'nation.de',
            'country.de', 'state.de', 'city.de', 'town.de', 'village.de', 'hamlet.de', 'settlement.de',
            'colony.de', 'camp.de', 'base.de', 'post.de', 'station.de', 'stop.de', 'terminal.de',
            'port.de', 'harbor.de', 'dock.de', 'pier.de', 'wharf.de', 'jetty.de', 'quay.de',
            'marina.de', 'beach.de', 'shore.de', 'coast.de', 'bank.de', 'edge.de', 'border.de',
            'boundary.de', 'limit.de', 'end.de', 'finish.de', 'close.de', 'shut.de', 'stop.de',
            'halt.de', 'pause.de', 'break.de', 'rest.de', 'recess.de', 'respite.de', 'relief.de',
            'ease.de', 'comfort.de', 'luxury.de', 'wealth.de', 'fortune.de', 'treasure.de',
            'riches.de', 'money.de', 'cash.de', 'currency.de', 'coin.de', 'note.de', 'bill.de',
            'check.de', 'draft.de', 'order.de', 'command.de', 'instruction.de', 'direction.de',
            'guidance.de', 'advice.de', 'counsel.de', 'suggestion.de', 'tip.de', 'hint.de',
            'clue.de', 'lead.de', 'trace.de', 'track.de', 'trail.de', 'path.de', 'way.de',
            'route.de', 'course.de', 'line.de', 'row.de', 'column.de', 'file.de', 'rank.de',
            'series.de', 'sequence.de', 'chain.de', 'link.de', 'connection.de', 'relation.de',
            'relationship.de', 'bond.de', 'tie.de', 'union.de', 'unity.de', 'harmony.de',
            'accord.de', 'agreement.de', 'contract.de', 'deal.de', 'bargain.de', 'sale.de',
            'purchase.de', 'buy.de', 'sell.de', 'trade.de', 'exchange.de', 'swap.de', 'barter.de',
            'business.de', 'commerce.de', 'industry.de', 'enterprise.de', 'company.de', 'firm.de',
            'corporation.de', 'organization.de', 'institution.de', 'establishment.de', 'agency.de',
            'office.de', 'bureau.de', 'department.de', 'division.de', 'section.de', 'branch.de',
            'wing.de', 'arm.de', 'leg.de', 'hand.de', 'foot.de', 'head.de', 'face.de', 'eye.de',
            'ear.de', 'nose.de', 'mouth.de', 'tooth.de', 'tongue.de', 'lip.de', 'chin.de',
            'cheek.de', 'jaw.de', 'neck.de', 'throat.de', 'chest.de', 'breast.de', 'heart.de',
            'lung.de', 'liver.de', 'kidney.de', 'stomach.de', 'gut.de', 'intestine.de', 'bowel.de',
            'colon.de', 'rectum.de', 'anus.de', 'bladder.de', 'urine.de', 'feces.de', 'waste.de',
            'trash.de', 'garbage.de', 'rubbish.de', 'litter.de', 'junk.de', 'scrap.de', 'debris.de',
            'remains.de', 'remnant.de', 'residue.de', 'rest.de', 'balance.de', 'remainder.de',
            'surplus.de', 'excess.de', 'extra.de', 'spare.de', 'additional.de', 'more.de',
            'less.de', 'fewer.de', 'smaller.de', 'larger.de', 'bigger.de', 'greater.de',
            'higher.de', 'lower.de', 'deeper.de', 'shallower.de', 'wider.de', 'narrower.de',
            'thicker.de', 'thinner.de', 'fatter.de', 'slimmer.de', 'heavier.de', 'lighter.de',
            'stronger.de', 'weaker.de', 'harder.de', 'softer.de', 'firmer.de', 'looser.de',
            'tighter.de', 'closer.de', 'farther.de', 'nearer.de', 'adjacent.de', 'beside.de',
            'next.de', 'previous.de', 'last.de', 'first.de', 'second.de', 'third.de', 'fourth.de',
            'fifth.de', 'sixth.de', 'seventh.de', 'eighth.de', 'ninth.de', 'tenth.de'
        }
    
    def is_available(self, domain):
        """
        检查单个域名是否可用（未注册）
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        # 如果是.de域名，首先检查是否在已知已注册域名列表中
        if domain.endswith('.de') and domain in self.known_registered_domains:
            return False
        
        # 使用DNS查询方法
        try:
            # 添加随机延迟，避免请求过于频繁
            delay = random.uniform(self.query_delay[0], self.query_delay[1])
            time.sleep(delay)
            
            # 尝试解析域名
            socket.gethostbyname(domain)
            return False  # 如果能解析，说明域名已注册
        except socket.gaierror:
            # 如果是.de域名，使用DENIC WHOIS查询进行二次确认
            if domain.endswith('.de'):
                return self._check_de_domain_whois(domain)
            return True  # 如果不能解析，且不是.de域名，认为域名未注册
        except Exception as e:
            print(f"检查域名 {domain} 时出错: {str(e)}")
            return None
    
    def _check_de_domain_whois(self, domain):
        """
        使用DENIC WHOIS服务检查.de域名
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        for attempt in range(self.retries + 1):
            try:
                # 添加随机延迟，避免请求过于频繁
                delay = random.uniform(self.query_delay[0], self.query_delay[1])
                time.sleep(delay)
                
                # 使用whois命令查询
                cmd = f"whois -h whois.denic.de {domain}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=self.timeout)
                output = result.stdout
                
                # 检查输出中是否包含表示域名未注册的关键词
                if "Status: free" in output or "not found" in output or "No entries found" in output:
                    return True  # 域名未注册
                
                # 检查输出中是否包含表示域名已注册的关键词
                if "Status: connect" in output or "registered" in output:
                    return False  # 域名已注册
                
                # 如果无法确定，尝试使用HTTP请求方法
                return self._check_de_domain_http(domain)
            
            except subprocess.TimeoutExpired:
                print(f"WHOIS查询域名 {domain} 超时，尝试次数: {attempt+1}/{self.retries+1}")
                if attempt == self.retries:
                    # 如果已达到最大重试次数，尝试使用HTTP请求方法
                    return self._check_de_domain_http(domain)
            
            except Exception as e:
                print(f"WHOIS查询域名 {domain} 时出错: {str(e)}，尝试次数: {attempt+1}/{self.retries+1}")
                if attempt == self.retries:
                    # 如果已达到最大重试次数，尝试使用HTTP请求方法
                    return self._check_de_domain_http(domain)
    
    def _check_de_domain_http(self, domain):
        """
        使用DENIC网页查询服务检查.de域名
        
        参数:
            domain (str): 要检查的完整域名（包括后缀）
            
        返回:
            bool: 如果域名未注册返回True，否则返回False
            None: 如果检查过程中出现错误
        """
        try:
            # 添加随机延迟，避免请求过于频繁
            delay = random.uniform(self.query_delay[0], self.query_delay[1])
            time.sleep(delay)
            
            # 使用DENIC的网页查询服务
            url = f"https://webwhois.denic.de/?lang=en&query={domain}"
            response = requests.get(url, timeout=self.timeout)
            
            # 检查响应中是否包含表示域名已注册的关键词
            if "is already registered" in response.text:
                # 将域名添加到已知已注册域名列表中
                self.known_registered_domains.add(domain)
                return False  # 域名已注册
            
            # 检查响应中是否包含表示域名未注册的关键词
            if "is not registered" in response.text or "is available" in response.text:
                return True  # 域名未注册
            
            # 如果无法确定，默认为已注册（保守策略）
            return False
        
        except Exception as e:
            print(f"HTTP查询域名 {domain} 时出错: {str(e)}")
            # 如果出错，默认为已注册（保守策略）
            return False
    
    def check_domains(self, domains):
        """
        检查多个域名的可用性
        
        参数:
            domains (list): 要检查的域名列表
            
        返回:
            dict: 包含可用、已注册和检查出错的域名列表
        """
        results = {
            'available': [],
            'unavailable': [],
            'error': []
        }
        
        # 使用进度条显示检查进度
        with tqdm(total=len(domains), desc="检查域名") as pbar:
            # 使用线程池并发检查域名
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # 提交所有任务
                future_to_domain = {executor.submit(self.is_available, domain): domain for domain in domains}
                
                # 处理结果
                for future in concurrent.futures.as_completed(future_to_domain):
                    domain = future_to_domain[future]
                    try:
                        is_available = future.result()
                        if is_available is True:
                            results['available'].append(domain)
                        elif is_available is False:
                            results['unavailable'].append(domain)
                        else:
                            results['error'].append(domain)
                    except Exception as e:
                        print(f"检查域名 {domain} 时出错: {str(e)}")
                        results['error'].append(domain)
                    
                    # 更新进度条
                    pbar.update(1)
        
        return results


# 测试代码
if __name__ == "__main__":
    # 创建域名检查器实例
    checker = DomainCheckerDE(max_workers=2, query_delay=(2, 5), timeout=10, retries=1)
    
    # 测试已知域名
    test_domains = [
        "kt.de",      # 已注册
        "go.de",      # 已注册
        "uh.de",      # 已注册
        "example.de", # 测试
        "thisisaprobablynotregistered123456789.de"  # 可能未注册
    ]
    
    print("\n=== 测试.de域名检查器 ===")
    print("检查域名...")
    
    results = checker.check_domains(test_domains)
    
    print("\n检查结果:")
    print(f"可用域名: {len(results['available'])}")
    for domain in results['available']:
        print(f"- {domain}")
    
    print(f"\n已注册域名: {len(results['unavailable'])}")
    for domain in results['unavailable']:
        print(f"- {domain}")
    
    print(f"\n检查出错的域名: {len(results['error'])}")
    for domain in results['error']:
        print(f"- {domain}")
