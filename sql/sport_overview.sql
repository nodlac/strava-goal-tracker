Select 
    case 
        when type like '%run%' then 'run' 
        when type like '%ride%' then 'ride' 
        else type end as a_type,
        sum(distance)*0.000621371,
        sum(elevation_gain)*3.28084,
        sum(duration)/ 3600.0  
FROM user_activities 
GROUP BY a_type;
