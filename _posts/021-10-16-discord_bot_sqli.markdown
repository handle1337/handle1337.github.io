---
layout: default
title:  "CVE-2021-37522 SQLi in Locke-Bot"
date:   2021-10-16 22:45:45 -0600
categories: jekyll update
---

This is a report I wrote for the developer of LockeBot, I hope you learn something from it :)

# Background

Multiple vulnerable functions and queries are found in the source code of [LockeBot 2.0.2](https://github.com/HKing2802/Locke-Bot/) which are susceptible to blind SQL injections.

## Why is this the case?

The application is vulnerable due to the fact that certain SQL queries include values which are controlled by the user with no sanitization and no prepared statements. The library that is supposed to mitigate this vulnerability and sanitize input is not implemented correctly in the bot. The library/module used for sanitization is called `sqlstring` and in it we can find the following function:

{% highlight javascript %}
SqlString.format = function format(sql, values, stringifyObjects, timeZone) {
  if (values == null) {
    return sql;
  }

  if (!Array.isArray(values)) {
    values = [values];
  }

  var chunkIndex        = 0;
  var placeholdersRegex = /\?+/g;
  var result            = '';
  var valuesIndex       = 0;
  var match;

  while (valuesIndex < values.length && (match = placeholdersRegex.exec(sql))) {
    var len = match[0].length;

    if (len > 2) {
      continue;
    }

    var value = len === 2
      ? SqlString.escapeId(values[valuesIndex])
      : SqlString.escape(values[valuesIndex], stringifyObjects, timeZone);

    result += sql.slice(chunkIndex, match.index) + value;
    chunkIndex = placeholdersRegex.lastIndex;
    valuesIndex++;
  }

  if (chunkIndex === 0) {
    // Nothing was replaced
    return sql;
  }

  if (chunkIndex < sql.length) {
    return result + sql.slice(chunkIndex);
  }

  return result;
};
{% endhighlight %}

Now, if we check the file `db.js` in LockeBot that is under the `/src` directory, we will find that this is the function being called to sanitize every query.

{% highlight javascript %}
function buildQuery(query) {
    if (!CONNECTED) throw Error('Not connected to a Database');
    return session.sql(SqlString.format(query));
}
{% endhighlight %}

## So what's the issue?

If we look closely at `SqlString.format`'s fuction body we can see that the first operation being done is an if statement:
{% highlight javascript %}
if (values == null) {
  return sql;
}
{% endhighlight %}

What this means is that if no values are fed into the `values` parameter, it will just return the sql value with no sanitization!

Now we take a look at LockeBot's implementation of this function again:
{% highlight javascript %}
return session.sql(SqlString.format(query));
{% endhighlight %}

No values are being passed! this is good ( for us at least :D ), it means that the bot is vulnerable to SQL Injection.

# Exploitation

While looking through the code I found a query under `/commands/mute.js` which grabs the user's discord username which is unsafely passed as a template literal. And of course there's also the issue of no sanitization occurring.

Exploiting this query is a bit difficult, since discord's username character limit is 32 there's barely any space to play around with. I was still able to exploit this vulnerability, but it wasn't as impactful as I would've liked it to be. However I'm sure there's queries in there that can be exploited more easily, and with much more impact.

This is what the query in question looks like:

{% highlight javascript %}
db.buildQuery(`INSERT INTO muted_users(user_id, name, member, time_unmute) VALUES (${target.id}, '${target.user.username}', ${member}, ${timeUnmute})`)
            .execute()
            .catch(err => { log(`Error in querying database in mute: ${err}`, message.client, false, 'error'); });
{% endhighlight %}

From here we can start building our payload. My first payload looked something like `',0,NULL); DO SLEEP(99)-- n`, however that didn't work since the bot was using MS SQL Server.

In the end the final payload that worked was: `', 0, (SELECT SLEEP(99))) -- n`

This payload will make the database "SLEEP" for 99 seconds which will stop any incoming queries from happening in that time.

## Breaking down the payload

The query should look something like this once you set the payload as your username and are then muted by an admin or mod:
{% highlight sql %}
INSERT INTO muted_users(user_id, name, member, time_unmute) VALUES (12345678, '', 0, (SELECT SLEEP(99))) -- n', 0, '2038-01-19 03:14:07')
{% endhighlight %}

The payload is exactly 30 characters which is within our limit of 32 characters. to comment the rest of the query out to avoid any SQL syntax errors we use `-- n` (the 'n' at the end is needed, otherwise discord gets rid of the trailing spaces) due to the DBMS used by the bot which is MySQL we are forced to sacrifice 2 characters for the `--` comment since otherwise it causes a syntax error.
NOTE: we aren't able to use `#` in this payload since discord won't let us put that character in our username.

Let's move on to the juicy bit `', 0, (SELECT SLEEP(99)))  -- n`
I'll make this one short

| Syntax      | Description |
| ----------- | ----------- |
| '      | Closes the username string column value so we can inject SQL |
| 0 | We set the member value to 0 |
| (SELECT SLEEP(99) | makes the DBMS sleep for 99 seconds |
| )) | Closes all the opened parentheses |
|  -- n | Comments out the trailing query |

# Impact

In this particular instance even though the limitations are many I was still able to execute a query that was decently impactful, if it wasn't for the 32 character limit I would've been able to drop tables, overwrite data, etc.

# Mitigation
This whole thing wouldn't have happened if prepared statements were used, or if the `sqlstring` library was used properly.

In the `README.md` file we can find proper use of the functions within:
{% highlight javascript %}
var userId = 1;
var sql = SqlString.format('SELECT * FROM users WHERE id = ?', [userId]);
console.log(sql); // SELECT * FROM users WHERE id = 1
{% endhighlight %}

